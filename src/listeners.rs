use std::io::prelude::*;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, UdpSocket};
use std::sync::mpsc::{Receiver as RReceiver, Sender as RSender};
use std::time::Instant;
use std::{io, thread};

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use uuid::Uuid;

use hex;
use types::*;

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

pub(crate) fn parse_ascii(packets: &[u8], captured_text_newline_seperator: &str) -> String {
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
