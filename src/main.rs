extern crate chrono;
extern crate config;
extern crate crossbeam_channel;
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

pub mod listeners;
pub mod settings;
pub mod types;

use std::fs::OpenOptions;
use std::io::prelude::*;
use std::sync::RwLock;
use std::thread;
use std::time::Duration;

use chrono::Local;
use crossbeam_channel::unbounded;
use mhteams::Message;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::blocking::Client;

use config::*;
use settings::load_defaults;
use std::sync::mpsc::channel;
use types::*;

const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const CFG_FILEPATHS: [&str; 4] = [
    "/etc/portsentinel/config.yml",
    "/etc/portsentinel/config.yaml",
    "config.yml",
    "config.yaml",
];

// Global mutable settings variable
lazy_static::lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new({
        let settings = load_defaults();

        settings
    });
}

fn main() {
    println!("PortSentinel v{}", VERSION);
    println!("{}", str::replace(env!("CARGO_PKG_AUTHORS"), ":", "\n"));

    //// Gather setting files
    // Create a channel to receive the write events to any configuration files
    let (tx, rx) = channel();
    // Automatically select the best implementation for the platform.
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_secs(2)).unwrap();

    let mut failed_paths: Vec<&str> = Vec::new();
    let mut succeeded_paths: Vec<&str> = Vec::new();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    for path in CFG_FILEPATHS.iter() {
        let res = watcher.watch(path, RecursiveMode::NonRecursive);
        match res {
            Ok(_) => {
                println!("Using file: {}", path);
                succeeded_paths.push(path);
                let test = SETTINGS.read().unwrap().parse_settings(path.to_string());
                match test {
                    None => {
                        // Add the new file to the global settings
                        SETTINGS.write().unwrap().add_source(path.to_string());
                    }
                    Some(err) => {
                        println!("Configuration Error: {}", err);
                    }
                }
            }
            Err(_) => {
                println!("Unable to find file: {}", path);
                failed_paths.push(path);
            }
        }
    }

    let settings = SETTINGS.read().unwrap().settings();
    if settings.print_config {
        show();
    }

    // Logging channels
    let (log_tx, log_rx) = unbounded();

    // Logging thread
    thread::spawn(move || {
        let client = Client::new();
        loop {
            let conn: LogEntry = log_rx.recv().unwrap();
            let settings = SETTINGS.read().unwrap().settings();
            let msg = parse_msg(conn.clone());

            if settings.screen_logging {
                println!("{}", msg);
            }
            if settings.file_logging {
                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(settings.file_logging_config.log_filepath.clone())
                    .expect("Failed to open local log file for writing");
                match conn.clone() {
                    LogEntry::LogEntryStart { .. } => {
                        writeln!(file, "{}", msg).unwrap();
                    }
                    LogEntry::LogEntryMsg { msgtype, .. } => match msgtype {
                        LogMsgType::Plaintext => {
                            if settings.file_logging_config.log_ascii {
                                writeln!(file, "{}", msg).unwrap();
                            }
                        }
                        LogMsgType::Hex => {
                            if settings.file_logging_config.log_hex {
                                writeln!(file, "{}", msg).unwrap();
                            }
                        }
                    },
                    LogEntry::LogEntryFinish { .. } => {
                        if settings.file_logging_config.log_disconnect {
                            writeln!(file, "{}", msg).unwrap();
                        }
                    }
                }
            }

            // TODO Fix Teams logging output
            if settings.teams_logging {
                let json_msg = Message::new().text(msg);
                match conn {
                    LogEntry::LogEntryStart { .. } => {
                        let _resp = client
                            .post(&settings.teams_logging_config.channel_url)
                            .json(&json_msg)
                            .send()
                            .unwrap();
                    }
                    LogEntry::LogEntryMsg { msgtype, .. } => match msgtype {
                        LogMsgType::Plaintext => {
                            if settings.teams_logging_config.log_ascii {
                                let _resp = client
                                    .post(&settings.teams_logging_config.channel_url)
                                    .json(&json_msg)
                                    .send()
                                    .unwrap();
                            }
                        }
                        LogMsgType::Hex => {
                            if settings.teams_logging_config.log_hex {
                                let _resp = client
                                    .post(&settings.teams_logging_config.channel_url)
                                    .json(&json_msg)
                                    .send()
                                    .unwrap();
                            }
                        }
                    },
                    LogEntry::LogEntryFinish { .. } => {
                        if settings.teams_logging_config.log_disconnect {
                            let _resp = client
                                .post(&settings.teams_logging_config.channel_url)
                                .json(&json_msg)
                                .send()
                                .unwrap();
                        }
                    }
                }
            }
        }
    });

    // Start up port listeners
    let mut listeners: Vec<PortListener> = Vec::new();
    for port in settings.ports.iter() {
        let port_spec = get_port_spec(&port, &settings);
        for port_num in port_spec.port_range {
            // Loop through each port and start a listener
            let single_port_spec = PortSpec {
                port_type: port_spec.port_type.clone(),
                port_range: port_num..=port_num,
                banner: port_spec.banner.clone(),
                bind_ip: port_spec.bind_ip,
                nfqueue: port_spec.nfqueue,
                io_timeout: port_spec.io_timeout,
            };
            listeners.push(PortListener::new(
                single_port_spec,
                settings.clone(),
                log_tx.clone(),
            ));
        }
    }

    loop {
        match rx.try_recv() {
            Ok(DebouncedEvent::Write(path)) => {
                println!(
                    " * {} written; refreshing configuration ...",
                    path.display()
                );

                let mut old_ports = Vec::new();
                for port in SETTINGS.read().unwrap().settings().ports {
                    let parsed_port = get_port_spec(&port, &settings);
                    for port_num in parsed_port.port_range {
                        let single_port = PortSpec {
                            port_type: parsed_port.port_type.clone(),
                            port_range: port_num..=port_num,
                            banner: parsed_port.banner.clone(),
                            bind_ip: parsed_port.bind_ip,
                            nfqueue: parsed_port.nfqueue,
                            io_timeout: parsed_port.io_timeout,
                        };
                        old_ports.push(single_port);
                    }
                }
                let mut test = (*SETTINGS.read().unwrap()).clone();
                let refresh_result = test
                    .refresh()
                    .expect("Unable to refresh")
                    .parse_settings(path.to_str().unwrap().to_string());
                if refresh_result.is_some() {
                    println!(
                        " * Error: {}. Reverting back to last working settings.",
                        refresh_result.unwrap()
                    );
                } else {
                    let _ = SETTINGS
                        .write()
                        .unwrap()
                        .add_source(path.to_str().unwrap().to_string());
                    println!(" * Successfully refreshed configuration.")
                }

                let mut new_ports = Vec::new();
                for port in SETTINGS.read().unwrap().settings().ports {
                    let parsed_port = get_port_spec(&port, &settings);
                    for port_num in parsed_port.port_range {
                        let single_port = PortSpec {
                            port_type: parsed_port.port_type.clone(),
                            port_range: port_num..=port_num,
                            banner: parsed_port.banner.clone(),
                            bind_ip: parsed_port.bind_ip,
                            nfqueue: parsed_port.nfqueue,
                            io_timeout: parsed_port.io_timeout,
                        };
                        new_ports.push(single_port);
                    }
                }

                // Find port listeners that are no longer in the configuration
                for port in old_ports.clone() {
                    if !new_ports.contains(&port) {
                        // TODO Add NFqueue "ports"
                        // println!("RM: {:#?}", port);
                        // let mut nfqueue = false;
                        // if port.nfqueue.is_some() {
                        //     nfqueue = true;
                        // }

                        // Now find the corresponding port listener and drop the value to stop listening
                        for (index, listener) in listeners.to_vec().iter().enumerate() {
                            if listener.get_port_spec().eq(&port) {
                                // println!("PS: {:#?}", listener.get_port_spec());
                                // println!("PS2: {:#?}", &port);
                                listener.kill();
                                listeners.remove(index);
                            }
                        }
                    }
                }

                // Find port listeners that need to be added
                for port in new_ports.clone() {
                    if !old_ports.contains(&port) {
                        // println!("NEW: {:#?}", port);
                        thread::sleep(Duration::from_secs(1));
                        listeners.push(PortListener::new(port, settings.clone(), log_tx.clone()));
                    }
                }

                // Use the new settings
                if SETTINGS.read().unwrap().settings().print_config {
                    show();
                }
            }

            Err(_err) => {
                let mut index = 0;
                for path in failed_paths.clone().iter() {
                    let res = watcher.watch(path, RecursiveMode::NonRecursive);
                    match res {
                        Ok(_) => {
                            println!("Adding new source: {}", path);
                            succeeded_paths.push(path);
                            failed_paths.remove(index);
                        }
                        Err(_) => {}
                    }
                    index += 1;
                }
                thread::sleep(Duration::from_secs(1));
            }

            _ => {
                // Ignore event
            }
        }
    }
}

fn parse_msg(conn: LogEntry) -> String {
    let current_time = Local::now();
    let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
    return match conn {
        LogEntry::LogEntryStart {
            uuid,
            transporttype,
            localip,
            localport,
            remoteip,
            remoteport,
        } => {
            format!(
                "[{}]: Connection-ID: {} {} DEST_IP {}:{} SRC_IP {}:{} ",
                formatted_time, uuid, transporttype, localip, localport, remoteip, remoteport
            )
        }
        LogEntry::LogEntryMsg {
            uuid,
            msg,
            msgtype,
            msglen,
        } => {
            format!(
                "[{}]: Connection-ID: {} {} {} Bytes: {}",
                formatted_time, uuid, msgtype, msglen, msg
            )
        }
        LogEntry::LogEntryFinish { uuid, duration } => {
            format!(
                "[{}]: Connection-ID: {} Connection Duration: {} seconds",
                formatted_time, uuid, duration
            )
        }
    };
}

fn show() {
    let settings = SETTINGS.read().unwrap().settings();
    println!(" * Settings :: \n\x1b[31m{:#?}\x1b[0m", settings);
}

fn get_port_spec(port: &PortType, settings: &AppConfig) -> PortSpec {
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
    };
    return port_spec;
}
