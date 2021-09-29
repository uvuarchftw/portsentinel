use config::{Config, ConfigError, File, Value};
use ipnet::IpNet;
use serde::de::Error;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::fmt;
use std::net::{TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::time::Duration;

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
            Ok(_test) => {
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
#[allow(non_camel_case_types)]
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

pub(crate) enum UpdateType {
    Die,
    BlacklistHosts(Vec<IpNet>),
    IOTimeout(Duration),
    NewlineSeparator(String),
}

#[derive(Debug)]
pub(crate) enum Sockets {
    Tcp(TcpListener),
    Udp(UdpSocket),
}

/// Get the port listening specification
pub(crate) fn get_port_spec(port: &PortType, settings: &AppConfig) -> PortSpec {
    let port_spec: PortSpec = match port {
        PortType::IcmpNfqueue {
            port_type,
            nfqueue,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: 0..=0,
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: Some(*nfqueue),
            io_timeout: settings.clone().io_timeout,
        },
        PortType::SinglePortNfqueue {
            port_type,
            port_num,
            nfqueue,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_num.clone()..=port_num.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: Some(nfqueue.clone()),
            io_timeout: settings.clone().io_timeout,
        },
        PortType::SinglePortBannerIoTimeout {
            port_type,
            port_num,
            banner,
            bind_ip,
            io_timeout,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_num.clone()..=port_num.clone(),
            banner: Some(banner.clone()),
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: io_timeout.clone(),
        },
        PortType::SinglePortBanner {
            port_type,
            port_num,
            banner,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_num.clone()..=port_num.clone(),
            banner: Some(banner.clone()),
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: settings.clone().io_timeout,
        },
        PortType::SinglePortIoTimeout {
            port_type,
            port_num,
            bind_ip,
            io_timeout,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_num.clone()..=port_num.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: io_timeout.clone(),
        },
        PortType::SinglePort {
            port_type,
            port_num,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_num.clone()..=port_num.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: settings.clone().io_timeout,
        },
        PortType::MultiPortNfqueue {
            port_type,
            port_range,
            bind_ip,
            nfqueue,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_range.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: Some(nfqueue.clone()),
            io_timeout: settings.clone().io_timeout,
        },
        PortType::MultiPortBannerIoTimeout {
            port_type,
            port_range,
            banner,
            bind_ip,
            io_timeout,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_range.clone(),
            banner: Some(banner.clone()),
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: io_timeout.clone(),
        },
        PortType::MultiPortBanner {
            port_type,
            port_range,
            banner,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_range.clone(),
            banner: Some(banner.clone()),
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: settings.clone().io_timeout,
        },
        PortType::MultiPortIoTimeout {
            port_type,
            port_range,
            bind_ip,
            io_timeout,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_range.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: io_timeout.clone(),
        },
        PortType::MultiPort {
            port_type,
            port_range,
            bind_ip,
        } => PortSpec {
            port_type: port_type.clone(),
            port_range: port_range.clone(),
            banner: None,
            bind_ip: bind_ip.clone(),
            nfqueue: None,
            io_timeout: settings.clone().io_timeout,
        },
    };
    return port_spec;
}
