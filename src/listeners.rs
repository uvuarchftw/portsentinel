use std::net::IpAddr;

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use std::sync::Arc;
use crate::types::*;
use uuid::Uuid;
use crossbeam_channel::Sender;
use nfq::Verdict;
use crate::log_nfqueue;

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

pub fn nfq_ipv4_callback(mut msg: nfq::Message, logchan: Sender<LogEntry>) {
    let mut unknown = false;
    // assume IPv4
    let ipv4_header = Ipv4Packet::new(msg.get_payload());
    match ipv4_header {
        Some(ipv4_header) => {
            match ipv4_header.get_next_level_protocol() {
                // IpNextHeaderProtocols::Icmp => handle_icmp_packet(
                //     msg.get_id(),
                //     IpAddr::V4(ipv4_header.get_source()),
                //     IpAddr::V4(ipv4_header.get_destination()),
                //     ipv4_header.payload(),
                // ),
                // IpNextHeaderProtocols::Udp => handle_udp_packet(
                //     msg.get_id(),
                //     IpAddr::V4(ipv4_header.get_source()),
                //     IpAddr::V4(ipv4_header.get_destination()),
                //     ipv4_header.payload(),
                // ),
                IpNextHeaderProtocols::Tcp => {
                    let tcp = TcpPacket::new(ipv4_header.payload());
                    match tcp {
                        Some(tcp) => {
                            let mac_array = msg.get_hw_addr();
                            let mac_addr = match mac_array {
                                None => {
                                    format!("MAC_GET_ERROR")
                                }
                                Some(mac_array) => {
                                    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5])
                                }
                            };
                            log_nfqueue(
                                logchan,
                                mac_addr,
                                msg.get_queue_num(),
                                TransportType::tcp,
                                ipv4_header.get_source().to_string(),
                                tcp.get_source(),
                                ipv4_header.get_destination().to_string(),
                                tcp.get_destination(),
                            );
                        }
                        None => {}
                    }

                    // let tcp = TcpPacket::new(ipv4_header.payload());
                    // if let Some(tcp) = tcp {
                    //     println!(
                    //         "TCP Packet: {}:{} > {}:{}; length: {}",
                    //         ipv4_header.get_source(),
                    //         tcp.get_source(),
                    //         ipv4_header.get_destination(),
                    //         tcp.get_destination(),
                    //         ipv4_header.payload().len(),
                    //         // msg.get_hw_addr().unwrap()
                    //     );
                    //     println!("tcp payload: {:?}", tcp.payload());
                    // } else {
                    //     println!("Malformed TCP Packet");
                    // }
                }
                //     handle_tcp_packet(
                //     msg.get_id(),
                //     IpAddr::V4(ipv4_header.get_source()),
                //     IpAddr::V4(ipv4_header.get_destination()),
                //     ipv4_header.payload(),
                // ),
                _ => {
                    unknown = true;
                }
            }
        }
        None => {
            unknown = true;
        }
    }

    msg.set_verdict(Verdict::Drop);
}

pub fn nfq_ipv6_callback(msg: nfq::Message) {
    // let mut unknown = false;
    // // Try IPv6
    // let ipv6_header = Ipv6Packet::new(msg.get_payload());
    // match ipv6_header {
    //     Some(ipv6_header) => match ipv6_header.get_next_header() {
    //         IpNextHeaderProtocols::Icmpv6 => handle_icmp_packet(
    //             msg.get_id(),
    //             IpAddr::V6(ipv6_header.get_source()),
    //             IpAddr::V6(ipv6_header.get_destination()),
    //             ipv6_header.payload(),
    //         ),
    //         IpNextHeaderProtocols::Udp => handle_udp_packet(
    //             msg.get_id(),
    //             IpAddr::V6(ipv6_header.get_source()),
    //             IpAddr::V6(ipv6_header.get_destination()),
    //             ipv6_header.payload(),
    //         ),
    //         IpNextHeaderProtocols::Tcp => handle_tcp_packet(
    //             msg.get_id(),
    //             IpAddr::V6(ipv6_header.get_source()),
    //             IpAddr::V6(ipv6_header.get_destination()),
    //             ipv6_header.payload(),
    //         ),
    //         _ => {
    //             unknown = true;
    //         }
    //     },
    //     None => {
    //         unknown = true;
    //     }
    // }
    //
    // msg.set_verdict(nfqueue::Verdict::Drop);
}
