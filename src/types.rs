use std::fmt;
use std::sync::mpsc::Sender;
use std::time::Duration;
use ipnet::IpNet;
use serde::{de, Deserialize, Deserializer};
use config::{Config, ConfigError, Value};
use std::collections::HashMap;
use std::ops::Range;
use serde::de::Error;

pub(crate) trait ShowSettings {
    fn settings(&self) -> AppConfig;
    fn parse_settings(&self) -> Option<ConfigError>;
}

impl ShowSettings for Config {
    fn settings<'e>(&self) -> AppConfig {
        let config = self.clone().try_into::<'e, AppConfig>().expect("Unable to parse settings");
        return config;
    }

    fn parse_settings<'e>(&self) -> Option<ConfigError>{
        let config = self.clone().try_into::<'e, AppConfig>().err();
        return config;
    }
}

fn de_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
{
    let duration = u32::deserialize(deserializer)?;
    Ok(Duration::from_secs(duration as u64))
}

fn de_range<'de, D>(deserializer: D) -> Result<Range<u16>, D::Error>
    where
        D: Deserializer<'de>,
{
    let range_str = String::deserialize(deserializer)?;
    let range: Vec<u16> = range_str.split("..").map(|x| x.parse::<u16>().unwrap()).collect();
    
    if range.len() != 2 || range[0] > range[1] {
        eprintln!("Invalid port range specified ({}..{})", range[0], range[1]);
        return Err(D::Error::custom("Bad port range"));
    }
    Ok(range[0]..range[1])
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScreenConfig {
    pub(crate) print_ascii: bool,
    pub(crate) print_hex: bool,
    pub(crate) print_disconnect: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileLoggingConfig {
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
    // pub(crate) bind_ips: Vec<IpNet>,
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

pub enum LogEntry {
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
    SinglePortNfqueueIoTimeout {
        port_type: TransportType,
        port_num: u16,
        nfqueue: u16,
        bind_ip: IpNet,
        #[serde(deserialize_with = "de_duration")]
        io_timeout: Duration,
    },
    SinglePortNfqueue {
        port_type: TransportType,
        port_num: u16,
        nfqueue: u16,
        bind_ip: IpNet,
    },
    SinglePortBanner {
        port_type: TransportType,
        port_num: u16,
        banner: String,
        bind_ip: IpNet,
    },
    SinglePort {
        port_type: TransportType,
        port_num: u16,
        bind_ip: IpNet,
    },
    MultiPort {
        port_type: TransportType,
        #[serde(deserialize_with = "de_range")]
        port_range: Range<u16>,
        bind_ip: IpNet,
    }
}

// #[derive(Debug, Clone, Deserialize)]
// pub struct Port {
//     pub(crate) port_num: u16,
//     pub(crate) port_type: TransportType,
//     pub(crate) banner: String,
//     pub(crate) nfqueue: u16,
//     pub(crate) bind_ip: IpNet,
//     #[serde(deserialize_with = "de_duration")]
//     pub(crate) io_timeout: Duration,
// }
//
// #[derive(Debug, Clone, Deserialize)]
// pub struct Port2 {
//     pub(crate) port_num: u16,
//     pub(crate) port_type: TransportType,
//     pub(crate) banner: String,
//     pub(crate) nfqueue: u16,
//     pub(crate) bind_ip: IpNet,
// }

pub struct State {
    pub(crate) count: u32,
}

impl State {
    pub fn new() -> State {
        State { count: 0 }
    }
}
