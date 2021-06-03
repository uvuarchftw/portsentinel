use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::Sender;
use std::time::Instant;
use std::{io, thread};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use uuid::Uuid;

use hex;
use types::*;
use State;

pub fn lurk_tcp(
    socket: TcpListener,
    settings: AppConfig,
    logchan: Sender<LogEntry>,
    meta_port: Port,
) {
    thread::spawn(move || {
        println!("Bound to {}:{}", meta_port.bind_ip, meta_port.port_num.unwrap());
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
                .set_read_timeout(Some(meta_port.io_timeout))
                .expect("Failed to set read timeout on TcpStream");
            stream
                .set_write_timeout(Some(meta_port.io_timeout))
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
                    transporttype: TransportType::Tcp,
                    remoteip: peer.ip().to_string(),
                    remoteport: peer.port(),
                    localip: local.ip().to_string(),
                    localport: local.port(),
                })
                .is_err()
            {
                println!("Failed to write LogEntry to logging thread");
            }

            let logchan = logchan.clone();
            let meta_port = meta_port.clone();
            let settings = settings.clone();
            thread::spawn(move || {
                let banner = meta_port.banner.unwrap().clone();
                // Write banner
                let start = Instant::now();
                if banner.len() > 0 {
                    match stream.write((*banner).as_bytes()) {
                        Ok(_) => println!(
                            "{:>5} > {}",
                            local.port(),
                            parse_text(banner.as_bytes(), settings.captured_text_newline_seperator.clone())
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
                let print_disconnect = settings.screen_config.print_disconnect;
                let log_disconnect = settings.file_logging_config.log_disconnect
                    || settings.teams_logging_config.log_disconnect;
                loop {
                    let print_disconnect = print_disconnect;
                    match stream.read(&mut buf) {
                        Ok(tcp_stream_length) => {
                            if tcp_stream_length == 0 {
                                let duration = start.elapsed().as_secs() as f32
                                    + start.elapsed().subsec_millis() as f32 / 1000.0;
                                // use Duration::as_float_secs() here as soon as it stabilizes
                                if print_disconnect {
                                    println!(
                                        "{:>5} - TCP FIN from {} after {:.1}s",
                                        local.port(),
                                        peer,
                                        duration
                                    );
                                }

                                if log_disconnect
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
                                local,
                                logchan.clone(),
                                settings.clone(),
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
    socket: UdpSocket,
    logchan: Sender<LogEntry>,
    settings: AppConfig,
    meta_port: Port,
) {
    thread::spawn(move || {
        let bind_ip = &settings.bind_ip;
        let meta_port = meta_port.clone();
        loop {
            let mut buf = [0; 2048];
            let con_uuid = Uuid::new_v4().to_hyphenated();
            let (number_of_bytes, src_addr) =
                socket.recv_from(&mut buf).expect("Didn't receive data");
            let filled_buf = &mut buf[..number_of_bytes];
            let banner = &meta_port.clone().banner.unwrap().clone();
            // Send banner
            socket
                .send_to(banner.as_bytes(), src_addr.to_string())
                .expect("couldn't send data");

            if logchan
                .send(LogEntry::LogEntryStart {
                    uuid: con_uuid,
                    transporttype: TransportType::Udp,
                    remoteip: src_addr.ip().to_string(),
                    remoteport: src_addr.port(),
                    localip: bind_ip.to_string(),
                    localport: meta_port.port_num.unwrap() as u16,
                })
                .is_err()
            {
                println!("Failed to write LogEntry to logging thread");
            }

            detect_msg(
                number_of_bytes,
                buf,
                socket.local_addr().unwrap(),
                logchan.clone(),
                settings.clone(),
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
                        transporttype: TransportType::Tcp,
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
    local: SocketAddr,
    logchan: Sender<LogEntry>,
    settings: AppConfig,
    con_uuid: uuid::adapter::Hyphenated,
) {
    let mut printable_text: Vec<u8> = Vec::new();
    for i in 0..len {
        // ASCII data, only allow newline or carriage return or US keyboard keys
        if packet_data_buffer[i] > 31 && packet_data_buffer[i] < 127 {
            printable_text.push(packet_data_buffer[i]);
        } else if packet_data_buffer[i] == 10 || packet_data_buffer[i] == 13 {
            for letter in settings.captured_text_newline_seperator
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
    if settings.screen_config.print_ascii {
        println!("{:>5} | {}", local.port(), ascii_text);
    }

    if (settings.file_logging_config.log_ascii
        || settings.teams_logging_config.log_ascii)
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
    if settings.screen_config.print_hex {
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
    if (settings.file_logging_config.log_hex
        || settings.teams_logging_config.log_hex)
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
    println!("{:>5} ! Read {} bytes from stream", local.port(), len);
}

pub(crate) fn parse_text(packet_data_buffer: &[u8], captured_text_newline_seperator: String) -> String {
    let mut printable_text: Vec<u8> = Vec::new();
    for i in 0..packet_data_buffer.len() {
        // ASCII data, only allow newline or carriage return or US keyboard keys
        if packet_data_buffer[i] > 31 && packet_data_buffer[i] < 127 {
            printable_text.push(packet_data_buffer[i]);
        } else if packet_data_buffer[i] == 10 || packet_data_buffer[i] == 13 {
            for letter in captured_text_newline_seperator
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
