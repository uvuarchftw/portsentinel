use std::net::{IpAddr, TcpListener, UdpSocket};

use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use crate::types::*;
use crate::{log_entry_msg, log_nfqueue};
use crossbeam_channel::{Receiver, Sender};
use ipnet::IpNet;
use nfq::{Message, Queue, Verdict};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

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
                    println!(
                        "ICMP Listener Unsupported. Can only receive ICMP from NFQueue {:#?}",
                        port_spec
                    )
                }
            },
            Some(queue_num) => {
                // This port listener will not have a socket set
                match port_spec.bind_ip {
                    IpNet::V4(_addr) => {
                        pl.bind_nfqueue(true);
                    }
                    IpNet::V6(_addr) => {
                        pl.bind_nfqueue(false);
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
                                                break;
                                            }
                                        }
                                        match stream.take_error() {
                                            Ok(opt) => {
                                                if opt.is_some() {
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

                                log_entry_msg(
                                    listener_self.logchan.clone(),
                                    &buf[0..number_of_bytes],
                                    con_uuid,
                                );
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
    fn bind_nfqueue(&self, ipv4: bool) {
        let listener_self = self.inner.clone();
        thread::spawn(move || {
            let queue = Arc::new(Mutex::new(
                Queue::open().expect("Unable to open NETLINK queue."),
            ));
            let nfqueue_num = listener_self.nfqueue.unwrap();
            queue
                .lock()
                .unwrap()
                .bind(nfqueue_num)
                .expect(format!("Unable to bind to NFQueue {}", nfqueue_num).as_str());
            println!("Bound to NFQueue {}", nfqueue_num);
            loop {
                match listener_self.update_rx.try_recv() {
                    Ok(update) => match update {
                        UpdateType::Die => {
                            break;
                        }
                        UpdateType::BlacklistHosts(hosts) => {
                            *listener_self.blacklist_hosts.lock().unwrap() = hosts;
                        }
                        _ => {}
                    },
                    Err(_) => {}
                }
                let msg = queue.lock().unwrap().recv().unwrap();
                if ipv4 {
                    nfq_ipv4_callback(msg, listener_self.logchan.clone());
                } else {
                    nfq_ipv6_callback(msg, listener_self.logchan.clone());
                }
            }
        });
    }
}

fn handle_icmp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let icmp = IcmpPacket::new(msg.get_payload());
    match icmp {
        Some(_icmp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::icmp,
                source.to_string(),
                0,
                destination.to_string(),
                0,
            );
        }
        None => {}
    }
}

fn handle_udp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let udp = UdpPacket::new(msg.get_payload());
    match udp {
        Some(udp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::udp,
                source.to_string(),
                udp.get_source(),
                destination.to_string(),
                udp.get_destination(),
            );
        }
        None => {}
    }
}

fn handle_tcp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let tcp = TcpPacket::new(msg.get_payload());
    match tcp {
        Some(tcp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::tcp,
                source.to_string(),
                tcp.get_source(),
                destination.to_string(),
                tcp.get_destination(),
            );
        }
        None => {}
    }
}

pub fn nfq_ipv4_callback(mut msg: nfq::Message, logchan: Sender<LogEntry>) {
    let mut unknown = false;
    // assume IPv4
    let ipv4_header = Ipv4Packet::new(msg.get_payload());
    match ipv4_header {
        Some(ipv4_header) => {
            let source = IpAddr::V4(ipv4_header.get_source());
            let dest = IpAddr::V4(ipv4_header.get_destination());
            match ipv4_header.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    handle_icmp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Udp => {
                    handle_udp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Tcp => {
                    handle_tcp_packet(logchan.clone(), &msg, source, dest)
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
    if unknown {
        eprintln!("Unknown packet");
    }

    msg.set_verdict(Verdict::Drop);
}

pub fn nfq_ipv6_callback(mut msg: nfq::Message, logchan: Sender<LogEntry>) {
    let mut unknown = false;
    // assume IPv4
    let ipv6_header = Ipv6Packet::new(msg.get_payload());
    match ipv6_header {
        Some(ipv6_header) => {
            let source = IpAddr::V6(ipv6_header.get_source());
            let dest = IpAddr::V6(ipv6_header.get_destination());
            match ipv6_header.get_next_header() {
                IpNextHeaderProtocols::Icmp => {
                    handle_icmp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Udp => {
                    handle_udp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Tcp => {
                    handle_tcp_packet(logchan.clone(), &msg, source, dest)
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
    if unknown {
        eprintln!("Unknown packet");
    }

    msg.set_verdict(Verdict::Drop);
}

fn get_mac_str(mac_array: Option<&[u8]>) -> String {
    let mac_addr = match mac_array {
        None => {
            format!("MAC_GET_ERROR")
        }
        Some(mac_array) => {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5]
            )
        }
    };
    return mac_addr;
}
