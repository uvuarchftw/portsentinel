extern crate chrono;
extern crate config;
extern crate crossbeam_channel;
extern crate hex;
extern crate ipnet;
extern crate libc;
extern crate mhteams;
extern crate nfq;
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
use std::time::{Duration, Instant};

use chrono::Local;
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError, Sender};
use mhteams::Message;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::blocking::Client;

use crate::listeners::PortListener;
use crate::settings::{load_defaults, show};
use crate::types::*;
use config::*;
use std::sync::mpsc::channel;

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

    //// Gather settings files
    // Create a channel to receive the write events to any configuration files
    let (watcher_tx, watcher_rx) = channel();
    // Automatically select the best implementation for the platform.
    let mut watcher: RecommendedWatcher = Watcher::new(watcher_tx, Duration::from_secs(2)).unwrap();

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
                let test = SETTINGS.read().unwrap().check_source(path.to_string());
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
    let (log_tx, log_rx): (Sender<LogEntry>, Receiver<LogEntry>) = unbounded();
    let (teams_tx, teams_rx): (Sender<(LogEntry, String)>, Receiver<(LogEntry, String)>) =
        unbounded();

    // Master Logging thread
    thread::spawn(move || {
        loop {
            match log_rx.recv() {
                Ok(conn) => {
                    // Get current global settings
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
                            LogEntry::LogEntryNFQueue { .. } => {
                                writeln!(file, "{}", msg).unwrap();
                            }
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

                    if settings.teams_logging {
                        let _ = teams_tx.send((conn, msg));
                    }
                }
                Err(_) => {}
            }
        }
    });

    // Teams Logging thread
    thread::spawn(move || {
        // Teams limit is 4 POST requests per second
        let client = Client::new();
        let duration = Duration::from_millis(500);
        loop {
            // Get current global settings
            let settings = SETTINGS.read().unwrap().settings();

            let mut teams_msg = "".to_string();
            teams_msg.clear();
            let deadline = Instant::now() + duration;
            loop {
                match teams_rx.recv_deadline(deadline) {
                    Ok((conn, entry_text)) => {
                        match conn {
                            LogEntry::LogEntryNFQueue { .. } => {
                                teams_msg += &entry_text;
                            }
                            LogEntry::LogEntryStart { .. } => {
                                teams_msg += &entry_text;
                            }
                            LogEntry::LogEntryMsg { msgtype, .. } => match msgtype {
                                LogMsgType::Plaintext => {
                                    if settings.teams_logging_config.log_ascii {
                                        teams_msg += &entry_text;
                                    }
                                }
                                LogMsgType::Hex => {
                                    if settings.teams_logging_config.log_hex {
                                        teams_msg += &entry_text;
                                    }
                                }
                            },
                            LogEntry::LogEntryFinish { .. } => {
                                if settings.teams_logging_config.log_disconnect {
                                    teams_msg += &entry_text;
                                }
                            }
                        }
                        teams_msg += &entry_text;
                    }
                    Err(RecvTimeoutError::Timeout) => break,
                    Err(_) => break,
                }
            }

            if teams_msg.is_empty() {
                // Nothing to send
                continue;
            } else {
                let json_msg = Message::new().text(teams_msg);
                let _resp = client
                    .post(&settings.teams_logging_config.channel_url)
                    .json(&json_msg)
                    .send()
                    .unwrap();
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
        // Wait for a change in the files
        match watcher_rx.try_recv() {
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
                    .check_source(path.to_str().unwrap().to_string());
                let parse_result = test.refresh().expect("Unable to parse").parse_settings();
                if refresh_result.is_some() || parse_result.is_some() {
                    if refresh_result.is_some() {
                        println!(
                            " * Error: {}. Reverting back to last working settings.",
                            refresh_result.unwrap()
                        );
                    } else if parse_result.is_some() {
                        println!(
                            " * Error: {}. Reverting back to last working settings.",
                            parse_result.unwrap()
                        );
                    }
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

                for port in old_ports.clone() {
                    // Find port listeners that are no longer in the configuration
                    if !new_ports.contains(&port) {
                        // println!("RM: {:#?}", port);

                        // Now find the corresponding port listener and drop the value to stop listening
                        for (index, listener) in listeners.to_vec().iter().enumerate() {
                            if listener.get_port_spec().eq(&port) {
                                listener.kill_listener();
                                // println!("Killed {:#?}", port);
                                listeners.remove(index);
                            }
                        }
                    }
                }

                // Update all of the global values of existing port listeners
                for listener in listeners.to_vec().iter() {
                    let settings = SETTINGS.read().unwrap().settings();
                    listener.update(UpdateType::BlacklistHosts(settings.blacklist_hosts.clone()));
                    listener.update(UpdateType::IOTimeout(settings.io_timeout));
                    listener.update(UpdateType::NewlineSeparator(
                        settings.captured_text_newline_separator.clone(),
                    ));
                }

                // Find port listeners that need to be added
                for port in new_ports.clone() {
                    if !old_ports.contains(&port) {
                        listeners.push(PortListener::new(port, settings.clone(), log_tx.clone()));
                    }
                }

                // Use the new settings
                if SETTINGS.read().unwrap().settings().print_config {
                    show();
                }
            }

            Err(_err) => {
                // Test to see if alternative configuration file paths are now available
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

/// Send message at the start of a connection (not nfqueue) to be logged
pub(crate) fn log_entry_msg(
    logchan: Sender<LogEntry>,
    packets: &[u8],
    con_uuid: uuid::adapter::Hyphenated,
) {
    let ascii_text: String = parse_ascii(packets);
    let mut hex_text: String = "".to_string();
    let data = hex::encode(packets.clone().to_vec());
    for line in data.lines() {
        hex_text += line;
    }

    if logchan
        .send(LogEntry::LogEntryMsg {
            uuid: con_uuid,
            msg: ascii_text.parse().unwrap(),
            msgtype: LogMsgType::Plaintext,
            msglen: packets.len(),
        })
        .is_err()
    {
        println!("Failed to write LogEntry to logging thread");
    }

    if logchan
        .send(LogEntry::LogEntryMsg {
            uuid: con_uuid,
            msg: hex_text,
            msgtype: LogMsgType::Hex,
            msglen: packets.len(),
        })
        .is_err()
    {
        println!("Failed to write LogEntry to logging thread");
    }
}

/// Send nfqueue message to be logged
pub(crate) fn log_nfqueue(
    logchan: Sender<LogEntry>,
    mac_addr: String,
    nfqueue_id: u16,
    transporttype: TransportType,
    remoteip: String,
    remoteport: u16,
    localip: String,
    localport: u16,
) {
    if logchan
        .send(LogEntry::LogEntryNFQueue {
            nfqueue_id,
            mac_addr,
            transporttype,
            remoteip,
            remoteport,
            localip,
            localport,
        })
        .is_err()
    {
        println!("Failed to write LogEntry to logging thread");
    }
}

/// Parse any ascii text from packet data
fn parse_ascii(packets: &[u8]) -> String {
    let captured_text_newline_seperator = SETTINGS
        .read()
        .unwrap()
        .settings()
        .captured_text_newline_separator;
    let mut printable_text: Vec<u8> = Vec::new();
    for i in 0..packets.len() {
        // ASCII data, only allow newline or carriage return or US keyboard keys
        if packets[i] > 31 && packets[i] < 127 {
            printable_text.push(packets[i]);
        } else if packets[i] == 10 || packets[i] == 13 {
            for letter in captured_text_newline_seperator.as_bytes() {
                printable_text.push(*letter);
            }
        }
    }
    let mut ascii_text: String = "".to_string();
    let data = String::from_utf8_lossy(printable_text.as_slice());
    for line in data.lines() {
        ascii_text += &*line.replace("\r", "");
    }
    return ascii_text;
}

/// Parse LogEntry and format it into a text message to be sent to the different logging parts
fn parse_msg(conn: LogEntry) -> String {
    let current_time = Local::now();
    let formatted_time = format!("{}", current_time.format("%a %d %b %Y - %H:%M.%S"));
    return match conn {
        LogEntry::LogEntryNFQueue {
            mac_addr,
            nfqueue_id,
            transporttype,
            localip,
            localport,
            remoteip,
            remoteport,
        } => {
            format!(
                "[{}]: NFQueue {} {} DEST_IP {}:{} SRC_IP {}:{} MAC_ADDR {}",
                formatted_time,
                nfqueue_id,
                transporttype,
                localip,
                localport,
                remoteip,
                remoteport,
                mac_addr
            )
        }
        LogEntry::LogEntryStart {
            uuid,
            transporttype,
            localip,
            localport,
            remoteip,
            remoteport,
        } => {
            format!(
                "[{}]: Connection-ID: {} {} DEST_IP {}:{} SRC_IP {}:{}",
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
