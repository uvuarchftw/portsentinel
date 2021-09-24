use std::net::IpAddr;

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use crate::log_nfqueue;
use crate::types::*;
use crossbeam_channel::Sender;
use nfq::{Message, Verdict};
use std::sync::Arc;
use uuid::Uuid;

fn handle_icmp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let icmp = IcmpPacket::new(msg.get_payload());
    match icmp {
        Some(_icmp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::icmp,
                source.to_string(),
                0,
                destination.to_string(),
                0,
            );
        }
        None => {}
    }
}

fn handle_udp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let udp = UdpPacket::new(msg.get_payload());
    match udp {
        Some(udp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::udp,
                source.to_string(),
                udp.get_source(),
                destination.to_string(),
                udp.get_destination(),
            );
        }
        None => {}
    }
}

fn handle_tcp_packet(
    logchan: Sender<LogEntry>,
    msg: &Message,
    source: IpAddr,
    destination: IpAddr,
) {
    let tcp = TcpPacket::new(msg.get_payload());
    match tcp {
        Some(tcp) => {
            let mac_addr = get_mac_str(msg.get_hw_addr());

            log_nfqueue(
                logchan,
                mac_addr,
                msg.get_queue_num(),
                TransportType::tcp,
                source.to_string(),
                tcp.get_source(),
                destination.to_string(),
                tcp.get_destination(),
            );
        }
        None => {}
    }
}

pub fn nfq_ipv4_callback(mut msg: nfq::Message, logchan: Sender<LogEntry>) {
    let mut unknown = false;
    // assume IPv4
    let ipv4_header = Ipv4Packet::new(msg.get_payload());
    match ipv4_header {
        Some(ipv4_header) => {
            let source = IpAddr::V4(ipv4_header.get_source());
            let dest = IpAddr::V4(ipv4_header.get_destination());
            match ipv4_header.get_next_level_protocol() {
                IpNextHeaderProtocols::Icmp => {
                    handle_icmp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Udp => {
                    handle_udp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Tcp => {
                    handle_tcp_packet(logchan.clone(), &msg, source, dest)
                }
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

pub fn nfq_ipv6_callback(mut msg: nfq::Message, logchan: Sender<LogEntry>) {
    let mut unknown = false;
    // assume IPv4
    let ipv6_header = Ipv6Packet::new(msg.get_payload());
    match ipv6_header {
        Some(ipv6_header) => {
            let source = IpAddr::V6(ipv6_header.get_source());
            let dest = IpAddr::V6(ipv6_header.get_destination());
            match ipv6_header.get_next_header() {
                IpNextHeaderProtocols::Icmp => {
                    handle_icmp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Udp => {
                    handle_udp_packet(logchan.clone(), &msg, source, dest)
                }
                IpNextHeaderProtocols::Tcp => {
                    handle_tcp_packet(logchan.clone(), &msg, source, dest)
                }
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

fn get_mac_str(mac_array: Option<&[u8]>) -> String {
    let mac_addr = match mac_array {
        None => {
            format!("MAC_GET_ERROR")
        }
        Some(mac_array) => {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac_array[0], mac_array[1], mac_array[2], mac_array[3], mac_array[4], mac_array[5]
            )
        }
    };
    return mac_addr;
}
