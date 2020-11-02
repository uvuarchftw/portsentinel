extern crate chrono;
extern crate libc;
extern crate nfqueue;
extern crate pnet;
extern crate regex;
extern crate uuid;
extern crate yaml_rust;
extern crate hex;
// extern crate mhteams;
// extern crate reqwest;

use std::fmt;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::net::{TcpListener, UdpSocket};
use std::process::exit;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use chrono::Local;
use regex::bytes::{RegexSet, RegexSetBuilder};
use yaml_rust::{Yaml, YamlLoader};
// use mhteams::{Message, Section, Image};
// use reqwest::blocking::Client;

use formatting::to_dotline;
use listeners::{lurk_tcp, lurk_udp, nfq_callback};

pub mod formatting;
pub mod listeners;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const BINARY_MATCHES: [(&str, &str); 34] = [
    // Global array, so needs an explicit length
    ("SSL3.0 Record Protocol", r"^\x16\x03\x00..\x01"),
    ("TLS1.0 Record Protocol", r"^\x16\x03\x01..\x01"),
    ("TLS1.1 Record Protocol", r"^\x16\x03\x02..\x01"),
    ("TLS1.2 Record Protocol", r"^\x16\x03\x03..\x01"),
    ("SSL3.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x00"),
    ("TLS1.0 CLIENT_HELLO", r"^\x16....\x01...\x03\x01"),
    ("TLS1.1 CLIENT_HELLO", r"^\x16....\x01...\x03\x02"),
    ("TLS1.2 CLIENT_HELLO", r"^\x16....\x01...\x03\x03"),
    ("SMB1 COMMAND NEGOTIATE", r"^....\xffSMB\x72"),
    ("SMB1 NT_STATUS Success", r"^....\xffSMB.[\x00-\x0f]"),
    ("SMB1 NT_STATUS Information", r"^....\xffSMB.[\x40-\x4f]"),
    ("SMB1 NT_STATUS Warning", r"^....\xffSMB.[\x80-\x8f]"),
    ("SMB1 NT_STATUS Error", r"^....\xffSMB.[\xc0-\xcf]"),
    ("SMB2 COMMAND NEGOTIATE", r"^\x00...\xfeSMB........\x00\x00"),
    ("SMB2 NT_STATUS Success", r"^\x00...\xfeSMB....[\x00-\x0f]"),
    (
        "SMB2 NT_STATUS Information",
        r"^\x00...\xfeSMB....[\x40-\x4f]",
    ),
    ("SMB2 NT_STATUS Warning", r"^\x00...\xfeSMB....[\x80-\x8f]"),
    ("SMB2 NT_STATUS Error", r"^\x00...\xfeSMB....[\xc0-\xcf]"),
    ("MS-TDS PRELOGIN Request", r"^\x12\x01\x00.\x00\x00"),
    ("MS-TDS LOGIN Request", r"^\x10\x01\x00.\x00\x00"),
    ("SOCKS4 NOAUTH Request", r"^\x04\x01\x00\x50"),
    ("SOCKS5 NOAUTH Request", r"^\x05\x01\x00$"), // Tested ok-ish
    ("SOCKS5 USER/PASS Request", r"^\x05\x02\x00\x02$"), // possibly broken
    ("Bitcoin main chain magic number", r"\xf9\xbe\xb4\xd9"),
    ("RFB3 (VNC) protocol handshake", r"^RFB 003\.00."),
    ("HTTP1 GET request", "^GET [^ ]+ HTTP/1"),
    ("HTTP1 POST request", "^POST [^ ]+ HTTP/1"),
    ("JSON RPC", r#"\{.*"jsonrpc".*\}"#),
    ("Android ADB CONNECT", r"^CNXN\x00\x00\x00\x01"),
    ("MS-RDP Connection Request", "Cookie: mstshash="),
    ("Generic payload dropper", r"(curl|wget)( |\+|%20)"),
    ("SQLdict MSSQL brute force tool", r"squelda 1.0"),
    ("MCTP REMOTE request", r"^REMOTE .*? MCTP/"),
    ("Kguard DVR auth bypass", r"^REMOTE HI_SRDK_.*? MCTP/"),
];

#[derive(Clone)]
pub struct AppConfig {
    print_ascii: bool,
    print_binary: bool,
    captured_text_newline_seperator: String,
    file_logging: bool,
    log_ascii: bool,
    log_binary: bool,
    log_disconnect: bool,
    nfqueue: Option<u16>,
    bind_ip: String,
    io_timeout: Duration,
    regexset: RegexSet,
}

#[derive(PartialEq, Eq)]
pub enum LogTransportType {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for LogTransportType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LogTransportType::Tcp => write!(f, "TCP"),
            LogTransportType::Udp => write!(f, "UDP"),
            LogTransportType::Icmp => write!(f, "ICMP"),
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
        transporttype: LogTransportType,
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
    number: u16,
    count: u64,
}

impl PartialEq for Port {
    fn eq(&self, other: &Port) -> bool {
        self.number == other.number
    }
}

pub struct State {
    ports: Vec<u16>,
    logchan: Sender<LogEntry>,
}

impl State {
    pub fn new(logchan: Sender<LogEntry>) -> State {
        State {
            ports: vec![],
            logchan,
        }
    }
}

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));

    let mut config_str = String::new();
    let mut file = match File::open("config.yml") {
        Ok(file) => file,
        Err(e) => {
            println!("Unable to open configuration file: {}", e.to_string());
            exit(-1);
        }
    };

    file.read_to_string(&mut config_str).unwrap();
    let docs = YamlLoader::load_from_str(&config_str).unwrap();
    let config = &docs[0];

    let app = AppConfig {
        print_ascii: false,
        print_binary: false,
        captured_text_newline_seperator: ".".to_string(),
        file_logging: false,
        log_ascii: false,
        log_binary: false,
        log_disconnect: false,
        nfqueue: None,
        bind_ip: String::new(),
        io_timeout: Duration::new(300, 0),
        regexset: RegexSet::new(&[] as &[&str]).unwrap(),
    };

    let configured_app = Arc::new(RwLock::new(parse_config(app, &config.clone())));

    let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
    for &(_, pattern) in BINARY_MATCHES.iter() {
        patterns.push(pattern);
    }
    configured_app.write().unwrap().regexset = RegexSetBuilder::new(patterns)
        .unicode(false)
        .dot_matches_new_line(false)
        .build()
        .unwrap();

    println!("\nStarting listeners on the following ports:");

    let (log_tx, log_rx) = channel();
    let file_logging = configured_app.read().unwrap().file_logging;
    thread::spawn(move || {
        // Logging thread
        loop {
            let conn: LogEntry = log_rx.recv().unwrap();
            let log_msg;
            if file_logging {
                let current_time = Local::now();
                let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("portsentinel.log")
                    .expect("Failed to open local log file for writing");
                match conn {
                    LogEntry::LogEntryStart {
                        uuid,
                        transporttype,
                        localip,
                        localport,
                        remoteip,
                        remoteport,
                    } => {
                        log_msg = format!(
                            "[{}]: Connection-ID: {} {} DEST_IP {}:{} SRC_IP {}:{} ",
                            formatted_time,
                            uuid,
                            transporttype,
                            localip,
                            localport,
                            remoteip,
                            remoteport
                        );
                        writeln!(file, "{}", log_msg).unwrap();
                    }
                    LogEntry::LogEntryMsg {
                        uuid,
                        msg,
                        msgtype,
                        msglen,
                    } => {
                        log_msg = format!(
                            "[{}]: Connection-ID: {} {} {} Bytes: {}",
                            formatted_time, uuid, msgtype, msglen, msg
                        );
                        writeln!(file, "{}", log_msg).unwrap();
                    }
                    LogEntry::LogEntryFinish { uuid, duration } => {
                        log_msg = format!(
                            "[{}]: Connection-ID: {} Connection Duration: {} seconds",
                            formatted_time, uuid, duration
                        );
                        writeln!(file, "{}", log_msg).unwrap();
                    }
                }
            }
            else if teams {
                // let msg = Message::new()
                //     .title("My title")
                //     .text("TL;DR: it's awesome 👍")
                //     .sections(vec![
                //         Section::new()
                //             .title("The **Section**")
                //             .activity_title("_Check this out_")
                //             .activity_subtitle("It's awesome")
                //             .activity_text("Lorum ipsum!"),
                //         Section::new()
                //             .title("Layin down some facts ✅")
                //             .facts(vec![
                //                 Fact::new("Name", "John Smith"),
                //                 Fact::new("Language", "Rust. What else?"),
                //             ]),
                //     ]);

                // let client = Client::new();
                // let resp = client
                //     .post('')
                //     .json(&msg)
                //     .send()?;
            }
        }
    });

    for port in config["ports"].as_vec().unwrap() {
        if !port["tcp"].is_badvalue() {
            let app = configured_app.clone();
            let logchan = log_tx.clone();
            let bind_ip = app.read().unwrap().bind_ip.clone();

            let portno = port["tcp"].as_i64().unwrap();
            println!("TCP port {}", portno);
            let mut banner = Arc::new(String::new());
            if let Some(x) = port["banner"].as_str() {
                Arc::get_mut(&mut banner).unwrap().push_str(x);
                println!("  with banner: {}", to_dotline(x.as_bytes()));
            }

            match TcpListener::bind((bind_ip.as_str(), portno as u16)) {
                Ok(socket) => lurk_tcp(app, socket, logchan, banner),
                Err(e) => println!("ERROR binding to {}: {}", portno, e.to_string()),
            };
        } else if !port["udp"].is_badvalue() {
            let app = configured_app.clone();
            let logchan = log_tx.clone();
            let bind_ip = app.read().unwrap().bind_ip.clone();

            let portno = port["udp"].as_i64().unwrap();
            println!("UDP port {}", portno);
            let mut banner = Arc::new(String::new());
            if let Some(x) = port["banner"].as_str() {
                Arc::get_mut(&mut banner).unwrap().push_str(x);
                println!("  with banner: {}", to_dotline(x.as_bytes()));
            }

            match UdpSocket::bind((bind_ip.as_str(), portno as u16)) {
                Ok(socket) => lurk_udp(app, socket, (bind_ip, portno as u16), logchan, banner),
                Err(e) => println!("ERROR binding to {}: {}", portno, e.to_string()),
            };
        } else {
            println!("Invalid port specification in configuration file");
        }
    }

    let nfqueue = configured_app.read().unwrap().nfqueue;
    if let Some(qid) = nfqueue {
        let logchan = log_tx.clone();
    } else {
        loop {
            thread::sleep(Duration::new(60, 0));
        } // Nothing to do in the main thread
    }
}

fn parse_config(mut app: AppConfig, config: &Yaml) -> AppConfig {
    if config["general"].is_badvalue() {
        println!("No 'general' section found in configuration file");
        exit(-1);
    }
    if config["ports"].is_badvalue() {
        println!("No 'ports' section found in configuration file");
        exit(-1);
    }

    if !config["general"]["bind_ip"].is_badvalue() {
        app.bind_ip = config["general"]["bind_ip"]
            .as_str()
            .expect("Invalid ['bind_ip'] value")
            .to_string();
        println!("Binding to external IP {}", app.bind_ip);
    } else {
        println!("No 'bind_ip' section found in configuration file");
        app.bind_ip = String::from("0.0.0.0");
        println!("Binding to default external IP {}", app.bind_ip);
    }

    if !config["general"]["print_ascii"].is_badvalue() {
        if config["general"]["print_ascii"].as_bool().unwrap() {
            app.print_ascii = true;
            println!("Printing ASCII");
        }
    } else {
        println!("Invalid ['print_ascii'] value");
        exit(-2);
    }
    if !config["general"]["print_binary"].is_badvalue() {
        if config["general"]["print_binary"].as_bool().unwrap() {
            app.print_binary = true;
            println!("Printing binary in hexadecimal");
        }
    } else {
        println!("Invalid ['print_binary'] value");
        exit(-2);
    }
    if !config["general"]["captured_text_newline_seperator"].is_badvalue() {
        app.captured_text_newline_seperator = config["general"]["captured_text_newline_seperator"].as_str().unwrap().parse().unwrap();
    }
    else {
        app.captured_text_newline_seperator = ".".to_string();
    }

    if !config["general"]["file_logging"].is_badvalue() {
        if config["general"]["file_logging"].as_bool().unwrap() {
            app.file_logging = true;
            println!("Logging to local text file");
        }
    } else {
        println!("Invalid ['file_logging'] value");
        exit(-2);
    }

    if !config["file_logging"]["log_ascii"].is_badvalue() {
        if config["file_logging"]["log_ascii"].as_bool().unwrap() {
            app.log_ascii = true;
            println!("Logging any detected ASCII to local text file");
        }
    } else {
        println!("Invalid ['file_logging']['log_ascii'] value");
        exit(-2);
    }

    if !config["file_logging"]["log_binary"].is_badvalue() {
        if config["file_logging"]["log_binary"].as_bool().unwrap() {
            app.log_binary = true;
            println!("Logging any binary (as hex) to local text file");
        }
    } else {
        println!("Invalid ['file_logging']['log_binary'] value");
        exit(-2);
    }

    if !config["file_logging"]["log_disconnect"].is_badvalue() {
        if config["file_logging"]["log_disconnect"].as_bool().unwrap() {
            app.log_disconnect = true;
            println!("Logging TCP connection times to local text file");
        }
    } else {
        println!("Invalid ['file_logging']['log_disconnect'] value");
        exit(-2);
    }

    if !config["general"]["nfqueue"].is_badvalue() {
        match config["general"]["nfqueue"].as_i64() {
            Some(queue) => {
                app.nfqueue = Some(queue as u16);
                println!(
                    "Receiving SYN packets from nfqueue {}",
                    app.nfqueue.unwrap()
                );
                println!("Example iptables rule to make this work:");
                println!(
                    "\n  iptables -A INPUT -p tcp --syn -j NFQUEUE --queue-num {} --queue-bypass",
                    app.nfqueue.unwrap()
                );
            }
            None => println!("Invalid ['nfqueue'] value"),
        };
    } else {
        println!("Unable to find ['general']['nfqueue'] section. Continuing...")
    }

    return app; // send our config to the main function
}
