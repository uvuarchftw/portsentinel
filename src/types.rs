use crate::settings::{de_duration, de_range};
use config::Value;
use ipnet::IpNet;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::net::{TcpListener, UdpSocket};
use std::ops::RangeInclusive;
use std::time::Duration;

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
