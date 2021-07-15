extern crate chrono;
extern crate config;
extern crate hex;
extern crate ipnet;
extern crate libc;
extern crate mhteams;
extern crate nfqueue;
extern crate notify;
extern crate pnet;
extern crate regex;
extern crate reqwest;
extern crate serde;
extern crate uuid;
extern crate crossbeam_channel;

pub mod listeners;
pub mod settings;
pub mod types;

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::Duration;

use chrono::Local;
use mhteams::Message;
use reqwest::blocking::Client;
use crossbeam_channel::{unbounded, Sender, Receiver};

use listeners::{listen_tcp, listen_udp, nfq_callback};
use settings::parse_config;
use types::*;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const CFG_FILEPATHS: [&str; 4] = [
    "/etc/portsentinel/config.yml",
    "/etc/portsentinel/config.yaml",
    "config.yml",
    "config.yaml",
];

use config::*;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher, Error};
use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::RwLock;
use std::thread::sleep;
use types::PortType::*;
use std::ops::Index;
use std::sync::mpsc::channel;

lazy_static::lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new({
        let mut settings = parse_config();

        settings
    });
}

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));
    if SETTINGS.read().unwrap().settings().print_config {
        show();
    }

    let (log_tx, log_rx) = unbounded();
    let (die_tx, die_rx) = unbounded();

    thread::spawn(move || {
        let settings = SETTINGS.read().unwrap().settings();
        // Logging thread
        let client = Client::new();
        loop {
            let conn: LogEntry = log_rx.recv().unwrap();
            let msg = parse_msg(conn);

            if settings.file_logging {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(settings.file_logging_config.log_filepath.clone())
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

    let settings = SETTINGS.read().unwrap().settings();
    for port in settings.ports.iter() {
        start_port_listener( port,settings.clone(), log_tx.clone(), die_rx.clone());
    }

    watch();
}

fn start_port_listener(port: &PortType, settings: AppConfig, logchan: Sender<LogEntry>, diechan: Receiver<DieRequest>) {
        let port_spec: PortSpec = match port {
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
                banner: None,
                bind_ip: bind_ip.clone(),
                nfqueue: None,
                io_timeout: settings.clone().io_timeout,
            },
            PortType::MultiPortBanner {
                port_type,
                port_range,
                banner,
                bind_ip,
            } => PortSpec {
                port_type: port_type.clone(),
                port_range: port_range.clone(),
                banner: None,
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
                io_timeout: settings.clone().io_timeout,
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
            _ => {
                panic!("Unknown PortType");
            }
        };
        match port_spec.nfqueue {
            Some(_) => {
                let mut q = nfqueue::Queue::new(State::new());
                q.open();

                println!("nfqueue example program: print packets metadata and accept packets");

                q.unbind(libc::AF_INET); // ignore result, failure is not critical here

                let rc = q.bind(libc::AF_INET);
                if rc != 0 {
                    println!("Unable to bind to nfqueue. Are you root?");
                } else {
                    println!("Successfully bound to nfqueue {}", 0);
                    q.create_queue(0, nfq_callback);
                    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

                    q.run_loop();
                }
            },
            None => {
                match port_spec.port_type {
                    TransportType::tcp => {
                        for port_num in port_spec.clone().port_range {
                            let bind_addr = format!("{}:{}", port_spec.bind_ip.addr(), port_num);
                            match TcpListener::bind(bind_addr.clone()) {
                                Ok(socket) => listen_tcp(socket, settings.clone(), logchan.clone(), diechan.clone(),port_spec.clone(), port_num),
                                Err(e) => println!("ERROR binding to {} TCP {}", bind_addr, e.to_string()),
                            };
                        }
                    }
                    TransportType::udp => {
                        for port_num in port_spec.clone().port_range {
                            let bind_addr = format!("{}:{}", port_spec.bind_ip.addr(), port_num);
                            match UdpSocket::bind(bind_addr.clone()) {
                                Ok(socket) => listen_udp(socket, settings.clone(), logchan.clone(), diechan.clone(),port_spec.clone(), port_num),
                                Err(e) => println!("ERROR binding to {} UDP {}", bind_addr, e.to_string()),
                            };
                        }
                    }
                    TransportType::icmp => {}
                    _ => {}
                }
            }
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

fn watch() {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Automatically select the best implementation for your platform.
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2)).unwrap();

    let mut failed_paths: Vec<&str> = Vec::new();
    let mut succeeded_paths: Vec<&str> = Vec::new();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    for path in CFG_FILEPATHS.iter() {
        let res = watcher
            .watch(path, RecursiveMode::NonRecursive);
        match res {
            Ok(_) => {
                println!("Using file: {}", path);
                succeeded_paths.push(path);
            }
            Err(_) => {
                println!("Unable to find file: {}", path);
                failed_paths.push(path);
            }
        }
    }

    loop {
        match rx.recv() {
            Ok(DebouncedEvent::Write(path)) => {
                println!(
                    " * {} written; refreshing configuration ...",
                    path.display()
                );

                let mut index = 0;
                for path in failed_paths.clone().iter() {
                    index += 1;
                    let res = watcher
                        .watch(path, RecursiveMode::NonRecursive);
                    match res {
                        Ok(_) => {
                            println!("Adding new source: {}", path);
                            succeeded_paths.push(path);
                            failed_paths.remove(index);
                        }
                        Err(_) => {
                            println!("Unable to find file: {}", path);
                        }
                    }
                }

                for path in succeeded_paths.clone().iter() {
                    // Check if path is still available
                    // let res = watcher
                    //     .watch(path, RecursiveMode::NonRecursive);
                    // match res {
                    //     Ok(_) => {
                    //         println!("Adding new source: {}", path);
                    //         succeeded_paths.push(path);
                    //     }
                    //     Err(_) => {
                    //         println!("Unable to find file: {}", path);
                    //         failed_paths.push(path);
                    //     }
                    // }
                }

                let mut test = (*SETTINGS.read().unwrap()).clone();
                let refresh_result = test.refresh().expect("Unable to refresh").parse_settings();
                if refresh_result.is_some() {
                    println!(
                        "Error: {}. Reverting back to last working settings.",
                        refresh_result.unwrap()
                    );
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
    let settings = SETTINGS.read().unwrap().settings();
    println!(" * Settings :: \n\x1b[31m{:#?}\x1b[0m", settings);
}
