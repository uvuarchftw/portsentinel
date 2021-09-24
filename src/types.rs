use config::{Config, ConfigError, File, Value};
use crossbeam_channel::{Receiver, Sender, unbounded};
use ipnet::IpNet;
use crate::listeners::{nfq_ipv4_callback, nfq_ipv6_callback};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fmt, io, thread};
use uuid::Uuid;
use crate::{log_entry_msg, log_nfqueue};
use nfq::{Queue, Verdict, Message};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::Packet;
use tokio::time::timeout;
use std::error::Error as std_err;
use serde::de::Error;
use tokio::sync::oneshot;
use futures_util::future::FutureExt;
use futures_util::Future;

pub(crate) trait AppSettings {
    fn settings(&self) -> AppConfig;
    fn parse_settings(&self) -> Option<ConfigError>;
    fn check_source(&self, new_source: String) -> Option<ConfigError>;
    fn add_source(&mut self, new_source: String);
}

impl AppSettings for Config {
    fn settings<'e>(&self) -> AppConfig {
        let config = self
            .clone()
            .try_into::<'e, AppConfig>()
            .expect("Unable to parse settings");
        return config;
    }

    fn parse_settings<'e>(&self) -> Option<ConfigError> {
        return match self.clone().try_into::<'e, AppConfig>() {
            Ok(_) => {
                // Configuration is valid
                return None;
            }
            Err(err) => Some(err),
        };
    }

    fn check_source<'e>(&self, new_source: String) -> Option<ConfigError> {
        let config = match self.clone().merge(File::with_name(&new_source)) {
            Ok(test) => {
                // println!("{:#?}", test);
                // Also check if parsing the configuration into AppSettings type will work too

                return None;
            }
            Err(err) => Some(err),
        };
        return config;
    }

    fn add_source<'e>(&mut self, new_source: String) {
        let _ = self.merge(File::with_name(&new_source)).unwrap();
    }
}

fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let duration = u32::deserialize(deserializer)?;
    Ok(Duration::from_secs(duration as u64))
}

fn de_range<'de, D>(deserializer: D) -> Result<RangeInclusive<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let range_str = String::deserialize(deserializer)?;
    let range: Vec<u16> = range_str
        .split("..")
        .map(|x| {
            let result = x.parse::<u16>();
            match result {
                Ok(x) => x,
                Err(_) => 0,
            }
        })
        .collect();

    if range[0] == 0 || range[1] == 0 {
        eprintln!("Invalid characters in port range specified ({})", range_str);
        return Err(D::Error::custom("Bad characters in port range"));
    } else if range.len() != 2 || range[0] > range[1] {
        eprintln!("Invalid port range specified ({}..{})", range[0], range[1]);
        return Err(D::Error::custom("Bad port range"));
    }
    Ok(range[0]..=range[1])
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScreenConfig {
    pub(crate) print_ascii: bool,
    pub(crate) print_hex: bool,
    pub(crate) print_disconnect: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileLoggingConfig {
    pub(crate) log_filepath: String,
    pub(crate) log_ascii: bool,
    pub(crate) log_hex: bool,
    pub(crate) log_disconnect: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TeamsLoggingConfig {
    pub(crate) channel_url: String,
    pub(crate) log_ascii: bool,
    pub(crate) log_hex: bool,
    pub(crate) log_disconnect: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AppConfig {
    pub(crate) blacklist_hosts: Vec<IpNet>,
    pub(crate) exit_on_error: bool,
    pub(crate) print_config: bool,
    pub(crate) captured_text_newline_separator: String,
    #[serde(rename = "io_timeout_seconds")]
    #[serde(deserialize_with = "de_duration")]
    pub(crate) io_timeout: Duration,
    pub(crate) screen_logging: bool,
    pub(crate) file_logging: bool,
    pub(crate) teams_logging: bool,

    #[serde(rename = "screen")]
    pub(crate) screen_config: ScreenConfig,
    #[serde(rename = "file")]
    pub(crate) file_logging_config: FileLoggingConfig,
    #[serde(rename = "teams")]
    pub(crate) teams_logging_config: TeamsLoggingConfig,

    #[serde(default)]
    pub(crate) ports: Vec<PortType>,

    #[serde(flatten)]
    pub unused: HashMap<String, Value>,
}

#[derive(PartialEq, Eq, Clone, Debug, Deserialize)]
pub enum TransportType {
    tcp,
    udp,
    icmp,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportType::tcp => write!(f, "TCP"),
            TransportType::udp => write!(f, "UDP"),
            TransportType::icmp => write!(f, "ICMP"),
        }
    }
}

#[derive(Clone)]
pub enum LogMsgType {
    Plaintext,
    Hex,
}

impl fmt::Display for LogMsgType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LogMsgType::Plaintext => write!(f, "Decoded Plaintext:"),
            LogMsgType::Hex => write!(f, "Full Hex Encoded Message:"),
        }
    }
}

#[derive(Clone)]
pub enum LogEntry {
    LogEntryNFQueue {
        nfqueue_id: u16,
        mac_addr: String,
        transporttype: TransportType,
        remoteip: String,
        remoteport: u16,
        localip: String,
        localport: u16,
    },
    LogEntryStart {
        uuid: uuid::adapter::Hyphenated,
        transporttype: TransportType,
        remoteip: String,
        remoteport: u16,
        localip: String,
        localport: u16,
    },
    LogEntryMsg {
        uuid: uuid::adapter::Hyphenated,
        msg: String,
        msgtype: LogMsgType,
        msglen: usize,
    },
    LogEntryFinish {
        uuid: uuid::adapter::Hyphenated,
        duration: f32,
    },
}

#[derive(PartialEq, Eq, Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum PortType {
    SinglePortNfqueue {
        port_type: TransportType,
        port_num: u16,
        nfqueue: u16,
        bind_ip: IpNet,
    },
    SinglePortBannerIoTimeout {
        port_type: TransportType,
        port_num: u16,
        banner: String,
        bind_ip: IpNet,
        #[serde(deserialize_with = "de_duration")]
        io_timeout: Duration,
    },
    SinglePortBanner {
        port_type: TransportType,
        port_num: u16,
        banner: String,
        bind_ip: IpNet,
    },
    SinglePortIoTimeout {
        port_type: TransportType,
        port_num: u16,
        bind_ip: IpNet,
        #[serde(deserialize_with = "de_duration")]
        io_timeout: Duration,
    },
    SinglePort {
        port_type: TransportType,
        port_num: u16,
        bind_ip: IpNet,
    },
    MultiPortNfqueue {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: RangeInclusive<u16>,
        bind_ip: IpNet,
        nfqueue: u16,
    },
    MultiPortBannerIoTimeout {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: RangeInclusive<u16>,
        banner: String,
        bind_ip: IpNet,
        #[serde(deserialize_with = "de_duration")]
        io_timeout: Duration,
    },
    MultiPortBanner {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: RangeInclusive<u16>,
        banner: String,
        bind_ip: IpNet,
    },
    MultiPortIoTimeout {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: RangeInclusive<u16>,
        bind_ip: IpNet,
        #[serde(deserialize_with = "de_duration")]
        io_timeout: Duration,
    },
    MultiPort {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: RangeInclusive<u16>,
        bind_ip: IpNet,
    },
    IcmpNfqueue {
        port_type: TransportType,
        nfqueue: u16,
        bind_ip: IpNet,
    },
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct PortSpec {
    pub(crate) port_type: TransportType,
    pub(crate) port_range: RangeInclusive<u16>,
    pub(crate) banner: Option<String>,
    pub(crate) bind_ip: IpNet,
    pub(crate) nfqueue: Option<u16>,
    pub(crate) io_timeout: Duration,
}

pub enum UpdateType {
    Die,
    BlacklistHosts(Vec<IpNet>),
    IOTimeout(Duration),
    NewlineSeparator(String),
}

#[derive(Debug)]
pub struct Listener {
    port_spec: PortSpec,
    port_type: TransportType,
    port_num: u16,
    blacklist_hosts: Mutex<Vec<IpNet>>,
    banner: Option<String>,
    socket: Option<Sockets>,
    nfqueue: Option<u16>,
    bind_ip: IpNet,
    io_timeout: Mutex<Duration>,
    captured_text_newline_separator: Mutex<String>,
    logchan: Sender<LogEntry>,
    update_rx: Receiver<UpdateType>,
    update_tx: Sender<UpdateType>,
}

impl Listener {
    /// Create and start a port listener
    pub(crate) fn new(
        port_spec: PortSpec,
        settings: AppConfig,
        logchan: Sender<LogEntry>,
    ) -> Listener {
        let (update_tx, update_rx) = crossbeam_channel::unbounded();

        let mut new_port_listener = Listener {
            port_spec: port_spec.clone(),
            port_type: port_spec.port_type,
            port_num: port_spec.port_range.into_inner().0,
            blacklist_hosts: Mutex::new(settings.blacklist_hosts),
            banner: port_spec.banner,
            socket: None,
            nfqueue: port_spec.nfqueue,
            bind_ip: port_spec.bind_ip,
            io_timeout: Mutex::new(port_spec.io_timeout),
            captured_text_newline_separator: Mutex::new(settings.captured_text_newline_separator),
            logchan,
            update_rx,
            update_tx,
        };

        if new_port_listener.nfqueue.is_none() {
            new_port_listener.bind_port();
        }

        return new_port_listener;
    }

    /// Bind port to address directly
    fn bind_port(&mut self) {
        let bind_addr = format!("{}:{}", self.bind_ip.addr(), self.port_num);
        match self.port_type {
            TransportType::tcp => {
                match TcpListener::bind(bind_addr.clone()) {
                    Ok(socket) => {
                        let _ = socket.set_nonblocking(true);
                        self.socket = Some(Sockets::Tcp(socket));
                    }
                    Err(e) => println!("ERROR binding to {} TCP {}", bind_addr, e.to_string()),
                };
            }
            TransportType::udp => {
                match UdpSocket::bind(bind_addr.clone()) {
                    Ok(socket) => {
                        let _ = socket.set_nonblocking(true);
                        self.socket = Some(Sockets::Udp(socket));
                    }
                    Err(e) => println!("ERROR binding to {} UDP {}", bind_addr, e.to_string()),
                };
            }
            TransportType::icmp => {}
        }
    }

    fn get_port_spec(&self) -> PortSpec {
        return self.port_spec.clone();
    }
}

#[derive(Debug, Clone)]
pub struct PortListener {
    inner: Arc<Listener>,
}

impl PortListener {
    pub(crate) fn new(
        port_spec: PortSpec,
        settings: AppConfig,
        logchan: Sender<LogEntry>,
    ) -> PortListener {
        let pl = PortListener {
            inner: Arc::new(Listener::new(port_spec.clone(), settings, logchan)),
        };

        match port_spec.nfqueue {
            None => match port_spec.port_type {
                TransportType::tcp => {
                    pl.tcp_listener();
                }
                TransportType::udp => {
                    pl.udp_listener();
                }
                TransportType::icmp => {
                    println!("ICMP Listener Unsupported. Can only receive ICMP from NFQueue {:#?}", port_spec)
                }
            },
            Some(queue_num) => {
                // This port listener will not have a socket set
                match port_spec.bind_ip {
                    IpNet::V4(_addr) => {
                        pl.bind_ipv4_nfqueue();
                    }
                    IpNet::V6(_addr) => {
                        pl.bind_ipv6_nfqueue();
                    }
                }
                match port_spec.port_type {
                    TransportType::icmp => {
                        println!("  Receiving packets from nfqueue {}", queue_num);
                        println!("  Example iptables rule to make this work:");
                        println!(
                            "    iptables -A INPUT -p ICMP -j NFQUEUE --queue-num {} --queue-bypass",
                            queue_num
                        );
                    }
                    _ => {
                        println!("  Receiving packets from nfqueue {}", queue_num);
                        println!("  Example iptables rule to make this work:");
                        println!(
                            "    iptables -A INPUT -p {} --dport {} -j NFQUEUE --queue-num {} --queue-bypass",
                            pl.inner.port_type.to_string(), pl.inner.port_num, queue_num
                        );
                    }
                }
            }
        }

        return pl;
    }

    pub(crate) fn get_port_spec(&self) -> PortSpec {
        return self.inner.get_port_spec();
    }

    pub(crate) fn kill_listener(&self) {
        let _ = self.inner.update_tx.send(UpdateType::Die);
    }

    pub(crate) fn update(&self, update: UpdateType) {
        let _ = self.inner.update_tx.send(update);
    }

    fn tcp_listener(&self) {
        let listener_self = self.inner.clone();
        thread::spawn(move || {
            match listener_self.socket.as_ref() {
                None => {}
                Some(sockets) => {
                    match sockets {
                        Sockets::Udp(_) => {}
                        Sockets::Tcp(socket) => {
                            println!(
                                "Bound to TCP {}:{}",
                                listener_self.bind_ip.addr(),
                                listener_self.port_num
                            );
                            for res in socket.incoming() {
                                let listener_self = listener_self.clone();
                                let mut stream = match res {
                                    Ok(stream) => stream,
                                    Err(_) => {
                                        // Kill thread if live configuration changes
                                        match listener_self.update_rx.try_recv() {
                                            Ok(update) => match update {
                                                UpdateType::Die => {
                                                    break;
                                                }
                                                UpdateType::BlacklistHosts(hosts) => {
                                                    let blacklist_hosts = &mut *listener_self
                                                        .blacklist_hosts
                                                        .lock()
                                                        .unwrap();
                                                    blacklist_hosts.clear();
                                                    for host in hosts {
                                                        blacklist_hosts.push(host);
                                                    }
                                                }
                                                UpdateType::IOTimeout(timeout) => {
                                                    *listener_self.io_timeout.lock().unwrap() =
                                                        timeout;
                                                }
                                                UpdateType::NewlineSeparator(separator) => {
                                                    *listener_self
                                                        .captured_text_newline_separator
                                                        .lock()
                                                        .unwrap() = separator;
                                                }
                                            },
                                            Err(_) => {}
                                        }
                                        thread::sleep(Duration::from_millis(50));
                                        continue;
                                    }
                                };
                                stream
                                    .set_read_timeout(Some(
                                        *listener_self.io_timeout.lock().unwrap(),
                                    ))
                                    .expect("Failed to set read timeout on TcpStream");
                                stream
                                    .set_write_timeout(Some(
                                        *listener_self.io_timeout.lock().unwrap(),
                                    ))
                                    .expect("Failed to set write timeout on TcpStream");
                                let local = stream.local_addr().unwrap();
                                let peer = match stream.peer_addr() {
                                    Ok(addr) => addr,
                                    Err(_e) => {
                                        // println!(
                                        //     "{:>5} ? TCP ERR GETADDR: {}",
                                        //     socket.local_addr().unwrap().port(),
                                        //     e.to_string()
                                        // );
                                        continue;
                                    }
                                };

                                // Check if host is in blacklist before sending
                                let mut in_blacklist = false;
                                for netmask in listener_self.blacklist_hosts.lock().unwrap().clone()
                                {
                                    if netmask.contains(&peer.ip()) {
                                        in_blacklist = true;
                                        break;
                                    }
                                }
                                if in_blacklist {
                                    // Skip this connection since it is a blacklisted IP
                                    continue;
                                }

                                let con_uuid = Uuid::new_v4().to_hyphenated();
                                if listener_self
                                    .logchan
                                    .send(LogEntry::LogEntryStart {
                                        uuid: con_uuid,
                                        transporttype: TransportType::tcp,
                                        remoteip: peer.ip().to_string(),
                                        remoteport: peer.port(),
                                        localip: local.ip().to_string(),
                                        localport: local.port(),
                                    })
                                    .is_err()
                                {
                                    println!("Failed to write LogEntry to logging thread");
                                }

                                let local_self = listener_self.clone();
                                thread::spawn(move || {
                                    // Create separate thread to follow TCP stream and allow for new ones to connect
                                    let banner =
                                        local_self.banner.clone().unwrap_or("".to_string());
                                    // Write banner
                                    let start = Instant::now();
                                    if banner.len() > 0 {
                                        match stream.write((*banner).as_bytes()) {
                                            Ok(_) => {}
                                            Err(_) => {
                                                // if e.kind() == io::ErrorKind::WouldBlock {
                                                //     println!(
                                                //         "{:>5} - TCP WRITE TIMEOUT from {}",
                                                //         local.port(),
                                                //         peer
                                                //     );
                                                // } else {
                                                //     println!(
                                                //         "{:>5} - TCP ERR WRITE to {}: {}",
                                                //         local.port(),
                                                //         peer,
                                                //         e.to_string()
                                                //     );
                                                // }
                                                return;
                                            }
                                        }
                                    }

                                    loop {
                                        // Kill thread if live configuration changes
                                        match local_self.update_rx.try_recv() {
                                            Ok(update) => {
                                                match update {
                                                    UpdateType::Die => {
                                                        break;
                                                    }
                                                    UpdateType::BlacklistHosts(hosts) => {
                                                        *listener_self
                                                            .blacklist_hosts
                                                            .lock()
                                                            .unwrap() = hosts;
                                                        println!("Updated blacklisthosts2, from {}\n{:#?}", listener_self.port_num, *listener_self.blacklist_hosts.lock().unwrap());
                                                    }
                                                    UpdateType::IOTimeout(timeout) => {
                                                        *listener_self.io_timeout.lock().unwrap() =
                                                            timeout;
                                                    }
                                                    UpdateType::NewlineSeparator(separator) => {
                                                        *listener_self
                                                            .captured_text_newline_separator
                                                            .lock()
                                                            .unwrap() = separator;
                                                    }
                                                }
                                            }
                                            Err(_) => {}
                                        }
                                        // Wait for response
                                        let mut buf: [u8; 4096] = [0; 4096];

                                        match stream.read(&mut buf) {
                                            Ok(tcp_stream_length) => {
                                                if tcp_stream_length == 0 {
                                                    let duration = start.elapsed().as_secs() as f32
                                                        + start.elapsed().subsec_millis() as f32
                                                            / 1000.0;

                                                    if local_self
                                                        .logchan
                                                        .send(LogEntry::LogEntryFinish {
                                                            uuid: con_uuid,
                                                            duration,
                                                        })
                                                        .is_err()
                                                    {
                                                        println!("Failed to write LogEntry to logging thread");
                                                    }
                                                    break;
                                                }

                                                log_entry_msg(
                                                    local_self.logchan.clone(),
                                                    &buf[0..tcp_stream_length],
                                                    con_uuid,
                                                );
                                            }
                                            Err(_) => {
                                                // if e.kind() == io::ErrorKind::WouldBlock {
                                                //     println!(
                                                //         "{:>5} - TCP READ TIMEOUT from {}",
                                                //         local.port(),
                                                //         peer
                                                //     );
                                                // } else {
                                                //     println!(
                                                //         "{:>5} - TCP ERR READ from {}: {}",
                                                //         local.port(),
                                                //         peer,
                                                //         e.to_string()
                                                //     );
                                                // }
                                                break;
                                            }
                                        }
                                        match stream.take_error() {
                                            Ok(opt) => {
                                                if opt.is_some() {
                                                    // println!(
                                                    //     "{:>5} - TCP ERR from {}: {}",
                                                    //     local.port(),
                                                    //     peer,
                                                    //     opt.unwrap().to_string()
                                                    // );
                                                    break;
                                                }
                                            }
                                            Err(_) => {
                                                println!("This shouldn't happen...");
                                                break;
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        });
    }

    fn udp_listener(&self) {
        let listener_self = self.inner.clone();
        // println!("{:#?}", local_self);
        thread::spawn(move || {
            println!(
                "Bound to UDP {}:{}",
                listener_self.bind_ip.addr(),
                listener_self.port_num
            );

            match listener_self
                .socket
                .as_ref()
                .expect("UDP Socket unavailable")
            {
                Sockets::Tcp(_) => {}
                Sockets::Udp(socket) => {
                    let banner = listener_self.banner.clone().unwrap_or("".to_string());
                    loop {
                        match listener_self.update_rx.try_recv() {
                            Ok(update) => match update {
                                UpdateType::Die => {
                                    break;
                                }
                                UpdateType::BlacklistHosts(hosts) => {
                                    *listener_self.blacklist_hosts.lock().unwrap() = hosts;
                                }
                                UpdateType::IOTimeout(timeout) => {
                                    *listener_self.io_timeout.lock().unwrap() = timeout;
                                }
                                UpdateType::NewlineSeparator(separator) => {
                                    *listener_self
                                        .captured_text_newline_separator
                                        .lock()
                                        .unwrap() = separator;
                                }
                            },
                            Err(_) => {}
                        }
                        let mut buf = [0; 4096];
                        let con_uuid = Uuid::new_v4().to_hyphenated();
                        match socket.recv_from(&mut buf) {
                            Ok((number_of_bytes, src_addr)) => {
                                // Send banner
                                socket
                                    .send_to(banner.as_bytes(), src_addr.to_string())
                                    .expect("Could not send data");

                                if listener_self
                                    .logchan
                                    .send(LogEntry::LogEntryStart {
                                        uuid: con_uuid,
                                        transporttype: TransportType::udp,
                                        remoteip: src_addr.ip().to_string(),
                                        remoteport: src_addr.port(),
                                        localip: listener_self.bind_ip.addr().to_string(),
                                        localport: listener_self.port_num,
                                    })
                                    .is_err()
                                {
                                    println!("Failed to write LogEntry to logging thread");
                                }

                                log_entry_msg(listener_self.logchan.clone(), &buf[0..number_of_bytes], con_uuid);
                            }
                            Err(_err) => {
                                thread::sleep(Duration::from_millis(50));
                            }
                        }
                    }
                }
            };
        });
    }

    /// Bind to NFQueue for port traffic
    fn bind_ipv4_nfqueue(&self) {
        let listener_self = self.inner.clone();
        thread::spawn(move || {
            let mut queue = Arc::new(Mutex::new(Queue::open().expect("Unable to open NETLINK queue.")));
            let nfqueue_num = listener_self.nfqueue.unwrap();
            queue.lock().unwrap().bind(nfqueue_num).expect(format!("Unable to bind to NFQueue {}", nfqueue_num).as_str());
            println!("Bound to NFQueue {}", nfqueue_num);
            queue.lock().unwrap().set_nonblocking(true);

            loop {
                match listener_self.update_rx.try_recv() {
                    Ok(update) => match update {
                        UpdateType::Die => {
                            println!("GOT DIE MSG");
                            break;
                        }
                        UpdateType::BlacklistHosts(hosts) => {
                            *listener_self.blacklist_hosts.lock().unwrap() = hosts;
                        }
                        _ => {}
                    },
                    Err(_) => {}
                }

                let msg_result = queue.lock().unwrap().recv();

                match msg_result {
                    Ok(mut msg) => {
                        let mac_array = msg.get_hw_addr();
                        let mac_addr = match mac_array {
                            None => {
                                format!("MAC_GET_ERROR")
                            }
                            Some(mac_array) => {
                                format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5])
                            }
                        };

                        let mut unknown = false;
                        // assume IPv4
                        let ipv4_header = Ipv4Packet::new(msg.get_payload());
                        match ipv4_header {
                            Some(ipv4_header) => {
                                match ipv4_header.get_next_level_protocol() {
                                    IpNextHeaderProtocols::Icmp => {
                                        let icmp_packet = IcmpPacket::new(ipv4_header.payload());
                                        match icmp_packet {
                                            Some(_icmp) => {
                                                log_nfqueue(
                                                    listener_self.logchan.clone(),
                                                    mac_addr,
                                                    msg.get_queue_num(),
                                                    TransportType::icmp,
                                                    ipv4_header.get_source().to_string(),
                                                    0,
                                                    ipv4_header.get_destination().to_string(),
                                                    0,
                                                );
                                            }
                                            None => {}
                                        }
                                    },
                                    IpNextHeaderProtocols::Udp => {
                                        let udp_packet = UdpPacket::new(ipv4_header.payload());
                                        match udp_packet {
                                            Some(udp) => {
                                                log_nfqueue(
                                                    listener_self.logchan.clone(),
                                                    mac_addr,
                                                    msg.get_queue_num(),
                                                    TransportType::udp,
                                                    ipv4_header.get_source().to_string(),
                                                    udp.get_source(),
                                                    ipv4_header.get_destination().to_string(),
                                                    udp.get_destination(),
                                                );
                                            }
                                            None => {}
                                        }
                                    },
                                    IpNextHeaderProtocols::Tcp => {
                                        let tcp_packet = TcpPacket::new(ipv4_header.payload());
                                        match tcp_packet {
                                            Some(tcp) => {
                                                log_nfqueue(
                                                    listener_self.logchan.clone(),
                                                    mac_addr,
                                                    msg.get_queue_num(),
                                                    TransportType::tcp,
                                                    ipv4_header.get_source().to_string(),
                                                    tcp.get_source(),
                                                    ipv4_header.get_destination().to_string(),
                                                    tcp.get_destination(),
                                                );
                                            }
                                            None => {}
                                        }
                                    }
                                    _ => {
                                        unknown = true;
                                    }
                                }
                            }
                            None => {
                                unknown = true;
                            }
                        }
                        msg.set_verdict(Verdict::Accept);
                        let _ = queue.lock().unwrap().verdict(msg).unwrap_or(());
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });
    }

    /// Bind to NFQueue for port traffic
    fn bind_ipv6_nfqueue(&self) {
        todo!();
        // let listener_self = self.inner.clone();
        // thread::spawn(move || {
        //     let mut queue = Queue::open().expect("Unable to open NETLINK queue.");
        //     let nfqueue_num = listener_self.nfqueue.unwrap();
        //     queue.bind(nfqueue_num).expect(format!("Unable to bind to NFQueue {}", nfqueue_num).as_str());
        //     println!("Bound to NFQueue {}", nfqueue_num);
        //     loop {
        //         match listener_self.update_rx.try_recv() {
        //             Ok(update) => match update {
        //                 UpdateType::Die => {
        //                     break;
        //                 }
        //                 UpdateType::BlacklistHosts(hosts) => {
        //                     *listener_self.blacklist_hosts.lock().unwrap() = hosts;
        //                 }
        //                 _ => {}
        //             },
        //             Err(_) => {}
        //         }
        //         let mut result_msg = queue.try_recv();
        //         match result_msg {
        //             Ok(mut msg) => {
        //                 let mac_array = msg.get_hw_addr();
        //                 let mac_addr = match mac_array {
        //                     None => {
        //                         format!("MAC_GET_ERROR")
        //                     }
        //                     Some(mac_array) => {
        //                         format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5])
        //                     }
        //                 };
        //
        //                 let mut unknown = false;
        //                 // assume IPv6
        //                 let ipv6_header = Ipv6Packet::new(msg.get_payload());
        //                 match ipv6_header {
        //                     Some(ipv6_header) => {
        //                         match ipv6_header.get_next_header() {
        //                             IpNextHeaderProtocols::Icmp => {
        //                                 let icmp_packet = IcmpPacket::new(ipv6_header.payload());
        //                                 match icmp_packet {
        //                                     Some(_icmp) => {
        //                                         log_nfqueue(
        //                                             listener_self.logchan.clone(),
        //                                             mac_addr,
        //                                             msg.get_queue_num(),
        //                                             TransportType::icmp,
        //                                             ipv6_header.get_source().to_string(),
        //                                             0,
        //                                             ipv6_header.get_destination().to_string(),
        //                                             0,
        //                                         );
        //                                     }
        //                                     None => {}
        //                                 }
        //                             },
        //                             IpNextHeaderProtocols::Udp => {
        //                                 let udp_packet = UdpPacket::new(ipv6_header.payload());
        //                                 match udp_packet {
        //                                     Some(udp) => {
        //                                         log_nfqueue(
        //                                             listener_self.logchan.clone(),
        //                                             mac_addr,
        //                                             msg.get_queue_num(),
        //                                             TransportType::udp,
        //                                             ipv6_header.get_source().to_string(),
        //                                             udp.get_source(),
        //                                             ipv6_header.get_destination().to_string(),
        //                                             udp.get_destination(),
        //                                         );
        //                                     }
        //                                     None => {}
        //                                 }
        //                             },
        //                             IpNextHeaderProtocols::Tcp => {
        //                                 let tcp_packet = TcpPacket::new(ipv6_header.payload());
        //                                 match tcp_packet {
        //                                     Some(tcp) => {
        //                                         log_nfqueue(
        //                                             listener_self.logchan.clone(),
        //                                             mac_addr,
        //                                             msg.get_queue_num(),
        //                                             TransportType::tcp,
        //                                             ipv6_header.get_source().to_string(),
        //                                             tcp.get_source(),
        //                                             ipv6_header.get_destination().to_string(),
        //                                             tcp.get_destination(),
        //                                         );
        //                                     }
        //                                     None => {}
        //                                 }
        //                             }
        //                             _ => {
        //                                 unknown = true;
        //                             }
        //                         }
        //                     }
        //                     None => {
        //                         unknown = true;
        //                     }
        //                 }
        //
        //                 msg.set_verdict(Verdict::Accept);
        //                 let _ = queue.verdict(msg).unwrap_or(());
        //             }
        //             Err(_) => {
        //                 thread::sleep(Duration::from_millis(50));
        //             }
        //         }
        //     }
        // });
    }
}

#[derive(Debug)]
enum Sockets {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

pub struct NFQueueState {
    port_type: TransportType,
    port_num: u16,
    blacklist_hosts: Mutex<Vec<IpNet>>,
    nfqueue_num: u16,
    bind_ip: IpNet,
    captured_text_newline_separator: Mutex<String>,
    pub(crate) logchan: Sender<LogEntry>,
    pub(crate) update_rx: Receiver<UpdateType>,
    pub(crate) update_tx: Sender<UpdateType>,
}

impl NFQueueState {
    pub fn new(
        listener: Arc<Listener>
    ) -> NFQueueState {
        NFQueueState {
            port_type: listener.port_type.clone(),
            port_num: listener.port_num.clone(),
            blacklist_hosts: Mutex::new(listener.blacklist_hosts.lock().unwrap().clone()),
            bind_ip: listener.bind_ip,
            captured_text_newline_separator: Mutex::new(listener.captured_text_newline_separator.lock().unwrap().clone()),
            logchan: listener.logchan.clone(),
            update_rx: listener.update_rx.clone(),
            update_tx: listener.update_tx.clone(),
            nfqueue_num: listener.nfqueue.unwrap(),
        }
    }
}
