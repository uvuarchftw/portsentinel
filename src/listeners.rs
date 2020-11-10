use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::Sender;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use std::{io, thread};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use uuid::Uuid;

use hex;
use State;
use BINARY_MATCHES;
use {AppConfig, LogEntry, LogMsgType, LogTransportType};

pub fn lurk_tcp(
    app: Arc<RwLock<AppConfig>>,
    socket: TcpListener,
    logchan: Sender<LogEntry>,
    banner: Arc<String>,
) {
    thread::spawn(move || {
        for res in socket.incoming() {
            let mut stream = match res {
                Ok(stream) => stream,
                Err(e) => {
                    println!(
                        "{:>5} ? TCP ERR ACCEPT: {}",
                        socket.local_addr().unwrap().port(),
                        e.to_string()
                    );
                    continue;
                }
            };
            stream
                .set_read_timeout(Some(app.read().unwrap().io_timeout))
                .expect("Failed to set read timeout on TcpStream");
            stream
                .set_write_timeout(Some(app.read().unwrap().io_timeout))
                .expect("Failed to set write timeout on TcpStream");
            let local = stream.local_addr().unwrap();
            let peer = match stream.peer_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    println!(
                        "{:>5} ? TCP ERR GETADDR: {}",
                        socket.local_addr().unwrap().port(),
                        e.to_string()
                    );
                    continue;
                }
            };

            println!("{:>5} + TCP ACK from {}", local.port(), peer);
            let con_uuid = Uuid::new_v4().to_hyphenated();
            if logchan
                .send(LogEntry::LogEntryStart {
                    uuid: con_uuid,
                    transporttype: LogTransportType::Tcp,
                    remoteip: peer.ip().to_string(),
                    remoteport: peer.port(),
                    localip: local.ip().to_string(),
                    localport: local.port(),
                })
                .is_err()
            {
                println!("Failed to write LogEntry to logging thread");
            }

            let app = app.clone();
            let banner = banner.clone();
            let logchan = logchan.clone();
            thread::spawn(move || {
                // Write banner
                let start = Instant::now();
                if banner.len() > 0 {
                    match stream.write((*banner).as_bytes()) {
                        Ok(_) => println!(
                            "{:>5} > {}",
                            local.port(),
                            parse_text(banner.as_bytes(), app.clone())
                        ),
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                println!("{:>5} - TCP WRITE TIMEOUT from {}", local.port(), peer);
                            } else {
                                println!(
                                    "{:>5} - TCP ERR WRITE to {}: {}",
                                    local.port(),
                                    peer,
                                    e.to_string()
                                );
                            }
                            return;
                        }
                    }
                }
                // Wait for response
                let mut buf: [u8; 2048] = [0; 2048];
                loop {
                    match stream.read(&mut buf) {
                        Ok(tcp_stream_length) => {
                            if tcp_stream_length == 0 {
                                let duration = start.elapsed().as_secs() as f32
                                    + start.elapsed().subsec_millis() as f32 / 1000.0;
                                // use Duration::as_float_secs() here as soon as it stabilizes
                                if app.read().unwrap().screen_config.print_disconnect {
                                    println!(
                                        "{:>5} - TCP FIN from {} after {:.1}s",
                                        local.port(),
                                        peer,
                                        duration
                                    );
                                }

                                if (app.read().unwrap().file_logging_config.log_disconnect
                                    || app.read().unwrap().teams_logging_config.log_disconnect)
                                    && logchan
                                        .send(LogEntry::LogEntryFinish {
                                            uuid: con_uuid,
                                            duration: duration,
                                        })
                                        .is_err()
                                {
                                    println!("Failed to write LogEntry to logging thread");
                                }
                                break;
                            }
                            detect_msg(
                                tcp_stream_length,
                                buf,
                                app.clone(),
                                local,
                                logchan.clone(),
                                con_uuid,
                            );
                        }
                        Err(e) => {
                            if e.kind() == io::ErrorKind::WouldBlock {
                                println!("{:>5} - TCP READ TIMEOUT from {}", local.port(), peer);
                            } else {
                                println!(
                                    "{:>5} - TCP ERR READ from {}: {}",
                                    local.port(),
                                    peer,
                                    e.to_string()
                                );
                            }
                            break;
                        }
                    }
                    match stream.take_error() {
                        Ok(opt) => {
                            if opt.is_some() {
                                println!(
                                    "{:>5} - TCP ERR from {}: {}",
                                    local.port(),
                                    peer,
                                    opt.unwrap().to_string()
                                );
                                break;
                            }
                        }
                        Err(_) => {
                            println!("This shouldn't happen...");
                            break;
                        }
                    }
                }
            });
        }
    });
}

pub fn lurk_udp(
    app: Arc<RwLock<AppConfig>>,
    socket: UdpSocket,
    local_bind: (String, u16),
    logchan: Sender<LogEntry>,
    banner: Arc<String>,
) {
    thread::spawn(move || {
        loop {
            let mut buf = [0; 2048];
            let con_uuid = Uuid::new_v4().to_hyphenated();
            let (number_of_bytes, src_addr) =
                socket.recv_from(&mut buf).expect("Didn't receive data");
            let filled_buf = &mut buf[..number_of_bytes];
            // Send banner
            socket
                .send_to(banner.as_bytes(), src_addr.to_string())
                .expect("couldn't send data");

            if logchan
                .send(LogEntry::LogEntryStart {
                    uuid: con_uuid,
                    transporttype: LogTransportType::Udp,
                    remoteip: src_addr.ip().to_string(),
                    remoteport: src_addr.port(),
                    localip: local_bind.0.clone(),
                    localport: local_bind.1,
                })
                .is_err()
            {
                println!("Failed to write LogEntry to logging thread");
            }

            detect_msg(
                number_of_bytes,
                buf,
                app.clone(),
                socket.local_addr().unwrap(),
                logchan.clone(),
                con_uuid,
            );
        }
    });
}

// TODO
pub fn nfq_callback(msg: &nfqueue::Message, state: &mut State) {
    let header = Ipv4Packet::new(msg.get_payload());
    match header {
        Some(h) => match h.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => match TcpPacket::new(h.payload()) {
                Some(p) => {
                    let remoteip = IpAddr::V4(h.get_source());
                    if !state.ports.contains(&p.get_destination()) {
                        println!(
                            "{:>5} = TCP SYN from {}:{} (unmonitored)",
                            p.get_destination(),
                            remoteip,
                            p.get_source()
                        );
                    } else {
                        println!(
                            "{:>5} = TCP SYN from {}:{}",
                            p.get_destination(),
                            remoteip,
                            p.get_source()
                        );
                    }
                    let con_uuid = Uuid::new_v4().to_hyphenated();
                    let _ = state.logchan.send(LogEntry::LogEntryStart {
                        uuid: con_uuid,
                        transporttype: LogTransportType::Tcp,
                        remoteip: remoteip.to_string(),
                        remoteport: p.get_source(),
                        localip: "".to_string(),
                        localport: p.get_destination(),
                    });
                }
                None => println!("Received malformed TCP packet"),
            },
            _ => println!("Received a non-TCP packet"),
        },
        None => println!("Received malformed IPv4 packet"),
    }

    msg.set_verdict(nfqueue::Verdict::Accept);
}

fn detect_msg(
    len: usize,
    packet_data_buffer: [u8; 2048],
    app: std::sync::Arc<std::sync::RwLock<AppConfig>>,
    local: SocketAddr,
    logchan: Sender<LogEntry>,
    con_uuid: uuid::adapter::Hyphenated,
) {
    let mut printable_text: Vec<u8> = Vec::new();
    for i in 0..len {
        // ASCII data, only allow newline or carriage return or US keyboard keys
        if packet_data_buffer[i] > 31 && packet_data_buffer[i] < 127 {
            printable_text.push(packet_data_buffer[i]);
        } else if packet_data_buffer[i] == 10 || packet_data_buffer[i] == 13 {
            for letter in app
                .read()
                .unwrap()
                .captured_text_newline_seperator
                .as_bytes()
            {
                printable_text.push(*letter);
            }
        }
    }
    let mut ascii_text: String = "".to_string();
    let data = String::from_utf8_lossy(printable_text.as_slice());
    for line in data.lines() {
        ascii_text += &*line.replace("\r", "");
    }
    if app.read().unwrap().screen_config.print_ascii {
        println!("{:>5} | {}", local.port(), ascii_text);
    }

    if (app.read().unwrap().file_logging_config.log_ascii
        || app.read().unwrap().teams_logging_config.log_ascii)
        && logchan
            .send(LogEntry::LogEntryMsg {
                uuid: con_uuid,
                msg: ascii_text.parse().unwrap(),
                msgtype: LogMsgType::Plaintext,
                msglen: len,
            })
            .is_err()
    {
        println!("Failed to write LogEntry to logging thread");
    }
    let packet_data_vector = packet_data_buffer[0..len].to_vec();
    if app.read().unwrap().screen_config.print_hex {
        let hex = hex::encode(packet_data_vector.clone());
        for line in hex.lines() {
            println!("{:>5} . {}", local.port(), line);
        }
    }
    let data = hex::encode(packet_data_vector.clone());
    let mut hex_text: String = "".to_string();
    for line in data.lines() {
        hex_text += line;
    }
    if (app.read().unwrap().file_logging_config.log_hex
        || app.read().unwrap().teams_logging_config.log_hex)
        && logchan
            .send(LogEntry::LogEntryMsg {
                uuid: con_uuid,
                msg: hex_text,
                msgtype: LogMsgType::Hex,
                msglen: len,
            })
            .is_err()
    {
        println!("Failed to write LogEntry to logging thread");
    }
    for id in app
        .read()
        .unwrap()
        .regexset
        .matches(&packet_data_buffer[..len])
        .into_iter()
    {
        println!(
            "{:>5} ^ Matches pattern {}",
            local.port(),
            BINARY_MATCHES[id].0
        );
    }
    println!("{:>5} ! Read {} bytes from stream", local.port(), len);
}

pub(crate) fn parse_text(packet_data_buffer: &[u8], app: Arc<RwLock<AppConfig>>) -> String {
    let mut printable_text: Vec<u8> = Vec::new();
    for i in 0..packet_data_buffer.len() {
        // ASCII data, only allow newline or carriage return or US keyboard keys
        if packet_data_buffer[i] > 31 && packet_data_buffer[i] < 127 {
            printable_text.push(packet_data_buffer[i]);
        } else if packet_data_buffer[i] == 10 || packet_data_buffer[i] == 13 {
            for letter in app
                .read()
                .unwrap()
                .captured_text_newline_seperator
                .as_bytes()
            {
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
