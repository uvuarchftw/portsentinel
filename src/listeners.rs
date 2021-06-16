use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::Sender;
use std::time::Instant;
use std::{io, thread};

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use uuid::Uuid;

use hex;
use types::*;

pub fn listen_tcp(
    socket: TcpListener,
    settings: AppConfig,
    logchan: Sender<LogEntry>,
    meta_port: Port,
) {
    thread::spawn(move || {
        println!(
            "Bound to TCP {}:{}",
            meta_port.bind_ip,
            meta_port.port_num.unwrap()
        );
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
                        Ok(_) => {}
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

                let print_disconnect = settings.screen_config.print_disconnect;
                let log_disconnect = settings.file_logging_config.log_disconnect
                    || settings.teams_logging_config.log_disconnect;
                loop {
                    // Wait for response
                    let mut buf: [u8; 4096] = [0; 4096];
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

                            log_packets(&buf, settings.clone(), logchan.clone(), local, con_uuid);
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

pub fn listen_udp(
    socket: UdpSocket,
    settings: AppConfig,
    logchan: Sender<LogEntry>,
    meta_port: Port,
) {
    thread::spawn(move || {
        println!(
            "Bound to UDP {}:{}",
            meta_port.bind_ip,
            meta_port.port_num.unwrap()
        );
        loop {
            let mut buf = [0; 4096];
            let con_uuid = Uuid::new_v4().to_hyphenated();
            let (_number_of_bytes, src_addr) =
                socket.recv_from(&mut buf).expect("Didn't receive data");
            let banner = &meta_port.clone().banner.unwrap().clone();
            // Send banner
            socket
                .send_to(banner.as_bytes(), src_addr.to_string())
                .expect("Could not send data");

            if logchan
                .send(LogEntry::LogEntryStart {
                    uuid: con_uuid,
                    transporttype: TransportType::Udp,
                    remoteip: src_addr.ip().to_string(),
                    remoteport: src_addr.port(),
                    localip: settings.bind_ip.clone(),
                    localport: meta_port.port_num.unwrap() as u16,
                })
                .is_err()
            {
                println!("Failed to write LogEntry to logging thread");
            }

            log_packets(
                &buf,
                settings.clone(),
                logchan.clone(),
                socket.local_addr().unwrap(),
                con_uuid,
            );
        }
    });
}

fn handle_icmp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    id,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    id,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                id,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
        println!("icmp payload: {:?}", icmp_packet.payload());
    } else {
        println!("[{}]: Malformed ICMP Packet", id);
    }
}

fn handle_udp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            id,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
        println!("udp payload: {:?}", udp.payload());
    } else {
        println!("[{}]: Malformed UDP Packet", id);
    }
}

fn handle_tcp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            id,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
        println!("tcp payload: {:?}", tcp.payload());
    } else {
        println!("[{}]: Malformed TCP Packet", id);
    }
}

pub fn nfq_callback(msg: &nfqueue::Message, state: &mut State) {

    // assume IPv4
    let header = Ipv4Packet::new(msg.get_payload());
    match header {
        Some(h) => match h.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => handle_icmp_packet(
                msg.get_id(),
                IpAddr::V4(h.get_source()),
                IpAddr::V4(h.get_destination()),
                h.payload(),
            ),
            IpNextHeaderProtocols::Udp => handle_udp_packet(
                msg.get_id(),
                IpAddr::V4(h.get_source()),
                IpAddr::V4(h.get_destination()),
                h.payload(),
            ),
            IpNextHeaderProtocols::Tcp => handle_tcp_packet(
                msg.get_id(),
                IpAddr::V4(h.get_source()),
                IpAddr::V4(h.get_destination()),
                h.payload(),
            ),
            _ => println!(
                "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                msg.get_id(),
                match IpAddr::V4(h.get_source()) {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                IpAddr::V4(h.get_source()),
                IpAddr::V4(h.get_destination()),
                h.get_next_level_protocol(),
                h.payload().len()
            ),
        },
        None => println!("Malformed IPv4 packet"),
    }

    state.count += 1;
    println!("count: {}", state.count);

    msg.set_verdict(nfqueue::Verdict::Accept);
    // let header = Ipv4Packet::new(msg.get_payload());
    // match header {
    //     Some(h) => match h.get_next_level_protocol() {
    //         IpNextHeaderProtocols::Tcp => match TcpPacket::new(h.payload()) {
    //             Some(p) => {
    //                 let remoteip = IpAddr::V4(h.get_source());
    //                 if !state.ports.contains(&p.get_destination()) {
    //                     println!(
    //                         "{:>5} = TCP SYN from {}:{} (unmonitored)",
    //                         p.get_destination(),
    //                         remoteip,
    //                         p.get_source()
    //                     );
    //                 } else {
    //                     println!(
    //                         "{:>5} = TCP SYN from {}:{}",
    //                         p.get_destination(),
    //                         remoteip,
    //                         p.get_source()
    //                     );
    //                 }
    //                 let con_uuid = Uuid::new_v4().to_hyphenated();
    //                 let _ = state.logchan.send(LogEntry::LogEntryStart {
    //                     uuid: con_uuid,
    //                     transporttype: TransportType::Tcp,
    //                     remoteip: remoteip.to_string(),
    //                     remoteport: p.get_source(),
    //                     localip: "".to_string(),
    //                     localport: p.get_destination(),
    //                 });
    //             }
    //             None => println!("Received malformed TCP packet"),
    //         },
    //         _ => println!("Received a non-TCP packet"),
    //     },
    //     None => println!("Received malformed IPv4 packet"),
    // }
    //
    // msg.set_verdict(nfqueue::Verdict::Accept);
}

fn log_packets(
    packets: &[u8],
    settings: AppConfig,
    logchan: Sender<LogEntry>,
    local: SocketAddr,
    con_uuid: uuid::adapter::Hyphenated,
) {
    let ascii_text: String = parse_ascii(packets, settings.captured_text_newline_seperator.clone());
    let mut hex_text: String = "".to_string();
    let data = hex::encode(packets.clone().to_vec());
    for line in data.lines() {
        hex_text += line;
    }

    if settings.screen_config.print_ascii {
        println!("{:>5} | {}", local.port(), ascii_text);
    }
    if settings.screen_config.print_hex {
        println!("{:>5} . {}", local.port(), hex_text);
    }

    if (settings.file_logging_config.log_ascii || settings.teams_logging_config.log_ascii)
        && logchan
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

    if (settings.file_logging_config.log_hex || settings.teams_logging_config.log_hex)
        && logchan
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

fn parse_ascii(packets: &[u8], captured_text_newline_seperator: String) -> String {
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
