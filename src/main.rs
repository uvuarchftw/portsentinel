extern crate chrono;
extern crate hex;
extern crate libc;
extern crate mhteams;
extern crate nfqueue;
extern crate pnet;
extern crate regex;
extern crate reqwest;
extern crate uuid;
extern crate yaml_rust;
#[macro_use]
extern crate lazy_static;

pub mod listeners;
pub mod settings;
pub mod types;

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
use mhteams::{Fact, Image, Message, Section};
use regex::bytes::{RegexSet, RegexSetBuilder};
use reqwest::blocking::Client;

use listeners::{lurk_tcp, lurk_udp, nfq_callback, parse_text};
use settings::parse_config;
use types::*;

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

lazy_static! {
    static ref SETTINGS: RwLock<AppConfig> = RwLock::new(parse_config());
}

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));

    // let mut patterns = Vec::with_capacity(BINARY_MATCHES.len());
    // for &(_, pattern) in BINARY_MATCHES.iter() {
    //     patterns.push(pattern);
    // }
    // configured_app.write().unwrap().regexset = RegexSetBuilder::new(patterns)
    //     .unicode(false)
    //     .dot_matches_new_line(false)
    //     .build()
    //     .unwrap();

    let (log_tx, log_rx) = channel();
    thread::spawn(move || {
        // Logging thread
        loop {
            let conn: LogEntry = log_rx.recv().unwrap();
            let msg = parse_msg(conn);

            if SETTINGS.read().unwrap().file_logging {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("portsentinel.log")
                    .expect("Failed to open local log file for writing");
                writeln!(file, "{}", msg).unwrap();
            }
            if SETTINGS.read().unwrap().teams_logging {
                let json_msg = Message::new().text(msg);

                let client = Client::new();
                let resp = client
                    .post(
                        &SETTINGS
                            .read()
                            .unwrap()
                            .teams_logging_config
                            .channel_url
                            .clone(),
                    )
                    .json(&json_msg)
                    .send()
                    .unwrap();
            }
        }
    });

    // for port in &SETTINGS.read().unwrap().ports {
    //     let logchan = log_tx.clone();
    //     match port.port_type {
    //         TransportType::Tcp => {},
    //         TransportType::Udp => {},
    //         TransportType::Icmp => {},
    //     }
    // }

    // for port in config["ports"].as_vec().unwrap() {
    //     if !port["tcp"].is_badvalue() {
    //         let logchan = log_tx.clone();
    //         let bind_ip = SETTINGS.read().unwrap().bind_ip.clone();
    //
    //         let portno = port["tcp"].as_i64().unwrap();
    //         println!("TCP port {}", portno);
    //         let mut banner = Arc::new(String::new());
    //         if let Some(x) = port["banner"].as_str() {
    //             Arc::get_mut(&mut banner).unwrap().push_str(x);
    //             println!("  with banner: {}", parse_text(x.as_bytes()));
    //         }
    //
    //         match TcpListener::bind((bind_ip.as_str(), portno as u16)) {
    //             Ok(socket) => lurk_tcp(socket, logchan, banner),
    //             Err(e) => println!("ERROR binding to {}: {}", portno, e.to_string()),
    //         };
    //     } else if !port["udp"].is_badvalue() {
    //         let logchan = log_tx.clone();
    //         let bind_ip = SETTINGS.read().unwrap().bind_ip.clone();
    //
    //         let portno = port["udp"].as_i64().unwrap();
    //         println!("UDP port {}", portno);
    //         let mut banner = Arc::new(String::new());
    //         if let Some(x) = port["banner"].as_str() {
    //             Arc::get_mut(&mut banner).unwrap().push_str(x);
    //             println!("  with banner: {}", parse_text(x.as_bytes()));
    //         }
    //
    //         match UdpSocket::bind((bind_ip.as_str(), portno as u16)) {
    //             Ok(socket) => lurk_udp(socket, (bind_ip, portno as u16), logchan, banner),
    //             Err(e) => println!("ERROR binding to {}: {}", portno, e.to_string()),
    //         };
    //     } else {
    //         println!("Invalid port specification in configuration file");
    //     }
    // }

    let nfqueue = SETTINGS.read().unwrap().nfqueue;
    if let Some(qid) = nfqueue {
        let logchan = log_tx.clone();
    } else {
        loop {
            thread::sleep(Duration::new(60, 0));
        } // Nothing to do in the main thread
    }
}

fn parse_msg(conn: LogEntry) -> String {
    let current_time = Local::now();
    let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
    match conn {
        LogEntry::LogEntryStart {
            uuid,
            transporttype,
            localip,
            localport,
            remoteip,
            remoteport,
        } => {
            return format!(
                "[{}]: Connection-ID: {} {} DEST_IP {}:{} SRC_IP {}:{} ",
                formatted_time, uuid, transporttype, localip, localport, remoteip, remoteport
            );
        }
        LogEntry::LogEntryMsg {
            uuid,
            msg,
            msgtype,
            msglen,
        } => {
            return format!(
                "[{}]: Connection-ID: {} {} {} Bytes: {}",
                formatted_time, uuid, msgtype, msglen, msg
            );
        }
        LogEntry::LogEntryFinish { uuid, duration } => {
            return format!(
                "[{}]: Connection-ID: {} Connection Duration: {} seconds",
                formatted_time, uuid, duration
            );
        }
    }
}
