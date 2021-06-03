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

pub mod listeners;
pub mod settings;
pub mod types;

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use chrono::Local;
use mhteams::{Fact, Image, Message, Section};
use reqwest::blocking::Client;

use listeners::{lurk_tcp, lurk_udp, nfq_callback, parse_text};
use settings::{parse_config, load_defaults};
use types::*;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));
    let default_settings: AppConfig = load_defaults();
    let settings1: AppConfig = parse_config(default_settings);

    let (log_tx, log_rx) = channel();

    let settings = settings1.clone();
    thread::spawn(move || {
        // Logging thread
        let client = Client::new();
        loop {
            let conn: LogEntry = log_rx.recv().unwrap();
            let msg = parse_msg(conn);

            if settings.file_logging {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("portsentinel.log")
                    .expect("Failed to open local log file for writing");
                writeln!(file, "{}", msg).unwrap();
            }
            if settings.teams_logging {
                let json_msg = Message::new().text(msg);
                let _resp = client
                    .post(&settings.teams_logging_config.channel_url)
                    .json(&json_msg)
                    .send()
                    .unwrap();
            }
        }
    });
    let settings = settings1.clone();

    for port in &settings.ports {
        let logchan = log_tx.clone();
        match port.port_type {
            TransportType::Tcp => {
                let bind_addr = format!("{}:{}", port.bind_ip, port.port_num.unwrap());
                match TcpListener::bind(bind_addr.clone()) {
                    Ok(socket) => lurk_tcp(socket, settings.clone(), logchan, port.clone()),
                    Err(e) => println!("ERROR binding to {} {}", bind_addr, e.to_string()),
                };
            },
            TransportType::Udp => {
                let bind_addr = format!("{}:{}", port.bind_ip, port.port_num.unwrap());
                match UdpSocket::bind(bind_addr.clone()) {
                    Ok(socket) => lurk_udp(socket, logchan, settings.clone(), port.clone()),
                    Err(e) => println!("ERROR binding to {} {}", bind_addr, e.to_string()),
                };
            },
            TransportType::Icmp => {},
        }
    }

    loop {
        thread::sleep(Duration::new(60, 0));
    } // Nothing to do in the main thread
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
