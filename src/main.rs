extern crate chrono;
extern crate config;
extern crate hex;
extern crate ipnet;
extern crate uuid;
extern crate libc;
extern crate mhteams;
extern crate nfqueue;
extern crate pnet;
extern crate regex;
extern crate reqwest;
extern crate serde;
extern crate notify;

// pub mod listeners;
pub mod settings;
pub mod types;

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;

use chrono::Local;
use mhteams::Message;
use reqwest::blocking::Client;

// use listeners::{listen_tcp, listen_udp, nfq_callback};
use settings::parse_config;
use types::*;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const CFG_FILEPATHS: [(&str); 4] = [
    "/etc/portsentinel/config.yml",
    "/etc/portsentinel/config.yaml",
    "config.yml",
    "config.yaml",
];


use config::*;
use std::collections::HashMap;
use std::sync::RwLock;
use notify::{RecommendedWatcher, DebouncedEvent, Watcher, RecursiveMode};

lazy_static::lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new({
        let mut settings = parse_config();

        settings
    });
}

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));

    // let (log_tx, log_rx) = channel();
    // thread::spawn(move || {
    //     // Logging thread
    //     let client = Client::new();
    //     loop {
    //         let conn: LogEntry = log_rx.recv().unwrap();
    //         let msg = parse_msg(conn);
    //
    //         if settings.file_logging {
    //             let mut file = OpenOptions::new()
    //                 .append(true)
    //                 .create(true)
    //                 .open("portsentinel.log")
    //                 .expect("Failed to open local log file for writing");
    //             writeln!(file, "{}", msg).unwrap();
    //         }
    //         if settings.teams_logging {
    //             let json_msg = Message::new().text(msg);
    //             let _resp = client
    //                 .post(&settings.teams_logging_config.channel_url)
    //                 .json(&json_msg)
    //                 .send()
    //                 .unwrap();
    //         }
    //     }
    // });
    //
    // let settings = app_settings.clone();
    // for port in &settings.ports {
    //     let logchan = log_tx.clone();
    //     if port.nfqueue.is_some() {
    //         let mut q = nfqueue::Queue::new(State::new());
    //         q.open();
    //
    //         println!("nfqueue example program: print packets metadata and accept packets");
    //
    //         q.unbind(libc::AF_INET); // ignore result, failure is not critical here
    //
    //         let rc = q.bind(libc::AF_INET);
    //         if rc != 0 {
    //             println!("Unable to bind to nfqueue. Are you root?");
    //             continue;
    //         } else {
    //             println!("Successfully bound to nfqueue {}", 0);
    //         }
    //
    //         q.create_queue(0, nfq_callback);
    //         q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
    //
    //         q.run_loop();
    //     } else {
    //         match port.port_type {
    //             TransportType::Tcp => {
    //                 let bind_addr = format!("{}:{}", port.bind_ip, port.port_num.unwrap());
    //                 match TcpListener::bind(bind_addr.clone()) {
    //                     Ok(socket) => listen_tcp(socket, settings.clone(), logchan, port.clone()),
    //                     Err(e) => println!("ERROR binding to {} TCP {}", bind_addr, e.to_string()),
    //                 };
    //             }
    //             TransportType::Udp => {
    //                 let bind_addr = format!("{}:{}", port.bind_ip, port.port_num.unwrap());
    //                 match UdpSocket::bind(bind_addr.clone()) {
    //                     Ok(socket) => listen_udp(socket, settings.clone(), logchan, port.clone()),
    //                     Err(e) => println!("ERROR binding to {} UDP {}", bind_addr, e.to_string()),
    //                 };
    //             }
    //             TransportType::Icmp => {}
    //         }
    //     }
    // }

    show();
    watch();
}

// fn parse_msg(conn: LogEntry) -> String {
//     let current_time = Local::now();
//     let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
//     match conn {
//         LogEntry::LogEntryStart {
//             uuid,
//             transporttype,
//             localip,
//             localport,
//             remoteip,
//             remoteport,
//         } => {
//             return format!(
//                 "[{}]: Connection-ID: {} {} DEST_IP {}:{} SRC_IP {}:{} ",
//                 formatted_time, uuid, transporttype, localip, localport, remoteip, remoteport
//             );
//         }
//         LogEntry::LogEntryMsg {
//             uuid,
//             msg,
//             msgtype,
//             msglen,
//         } => {
//             return format!(
//                 "[{}]: Connection-ID: {} {} {} Bytes: {}",
//                 formatted_time, uuid, msgtype, msglen, msg
//             );
//         }
//         LogEntry::LogEntryFinish { uuid, duration } => {
//             return format!(
//                 "[{}]: Connection-ID: {} Connection Duration: {} seconds",
//                 formatted_time, uuid, duration
//             );
//         }
//     }
// }

fn watch() {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Automatically select the best implementation for your platform.
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2)).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    for path in CFG_FILEPATHS.iter() {
        watcher.watch(path, RecursiveMode::NonRecursive).map_err( |e| {
            println!("Unable to find file: {}", path)
        });
    }

    loop {
        match rx.recv() {
            Ok(DebouncedEvent::Write(path)) => {
                println!(" * {} written; refreshing configuration ...", path.display());

                let mut test = (*SETTINGS.read().unwrap()).clone();
                let refresh_result = test.refresh().expect("Unable to refresh").parse_settings();
                if refresh_result.is_some() {
                    println!("Error: {}. Reverting back to last working settings.", refresh_result.unwrap());
                } else {
                    SETTINGS.write().unwrap().refresh();
                }

                show();
            }

            Err(e) => println!("watch error: {:?}", e),

            _ => {
                // Ignore event
            }
        }
    }
}

fn show() {
    let settings = SETTINGS
        .read()
        .unwrap().settings();
    println!(" * Settings :: \n\x1b[31m{:#?}\x1b[0m",
             settings);
}