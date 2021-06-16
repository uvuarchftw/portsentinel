use std::fmt;
use std::sync::mpsc::Sender;
use std::time::Duration;

#[derive(Clone)]
pub struct ScreenConfig {
    pub(crate) print_ascii: bool,
    pub(crate) print_hex: bool,
    pub(crate) print_disconnect: bool,
}

#[derive(Clone)]
pub struct FileLoggingConfig {
    pub(crate) log_ascii: bool,
    pub(crate) log_hex: bool,
    pub(crate) log_disconnect: bool,
}

#[derive(Clone)]
pub struct TeamsLoggingConfig {
    pub(crate) channel_url: String,
    pub(crate) log_ascii: bool,
    pub(crate) log_hex: bool,
    pub(crate) log_disconnect: bool,
}

#[derive(Clone)]
pub struct AppConfig {
    pub(crate) bind_ip: String,
    pub(crate) file_logging: bool,
    pub(crate) teams_logging: bool,
    pub(crate) captured_text_newline_seperator: String,

    pub(crate) screen_config: ScreenConfig,
    pub(crate) file_logging_config: FileLoggingConfig,
    pub(crate) teams_logging_config: TeamsLoggingConfig,

    pub(crate) io_timeout: Duration,
    pub(crate) ports: Vec<Port>,
}

#[derive(PartialEq, Eq, Clone)]
pub enum TransportType {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TransportType::Tcp => write!(f, "TCP"),
            TransportType::Udp => write!(f, "UDP"),
            TransportType::Icmp => write!(f, "ICMP"),
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

#[derive(Clone)]
pub struct Port {
    pub(crate) port_num: Option<u16>,
    pub(crate) port_type: TransportType,
    pub(crate) banner: Option<String>,
    pub(crate) nfqueue: Option<u16>,
    pub(crate) bind_ip: String,
    pub(crate) io_timeout: Duration,
}

pub struct State {
    pub(crate) count: u32,
}

impl State {
    pub fn new() -> State {
        State { count: 0 }
    }
}
