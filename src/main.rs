extern crate pnet;

mod rtp_packet;
mod rtp_stats;
use crate::rtp_packet::{RtpHeader, RtpPacket};
use crate::rtp_stats::{RtpInfo, RtpStats};
use pnet::datalink::{self, NetworkInterface};

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;

#[macro_use] extern crate prettytable;

use std::env;
use std::io::{self, Write};
use std::net::IpAddr;
use std::process;
use std::collections::HashMap;


const CLEAR_CODE: &str = "\x1B[2J"; 
const MOVE_TO_TOP_LEFT: &str = "\x1B[H";


fn get_interface_ips() -> HashMap<String, IpAddr> {
    let interfaces = datalink::interfaces();

    let interface_ip_map: HashMap<String, IpAddr> = interfaces
        .into_iter() 
        .filter_map(|iface| {
            let name = iface.name;
            if !iface.ips.is_empty() {
                let first_ip = iface.ips[0].ip(); 
                Some((name, first_ip))
            } else {
                None
            }
        })
        .collect();
        interface_ip_map
}


fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        if let Some(rtp) = RtpPacket::new(&packet[8..]){ // UDP header is 8 bytes
            println!("[udp]: {}:{} -> {}:{}", source, udp.get_source(), destination, udp.get_destination());  
            println!("{:?}", rtp.header);

        }
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp { 
        let magic_numeric = 0x24; // RTP over TCP magic number
        if packet.len() < 4 || packet[0] != magic_numeric {
            return; 
        }     
        if let Some(rtp) = RtpPacket::new(&packet[4..]){ // TCP header is variable, but RTP over TCP usually uses 4-byte length prefix
                println!("[tcp]: {}:{} -> {}:{}", source, tcp.get_source(), destination, tcp.get_destination());  
                println!("{:?}", rtp.header);

        }
    } 
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet)
        }
        
        _ => {}
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}


fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket) {
    let interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        _ => {}
    }
}

fn print_usage_and_exit() {
    let interfaces = get_interface_ips();
    writeln!(io::stderr(), "USAGE: sniff-rtp <NETWORK INTERFACE>").unwrap();
    println!("Available interfaces and their IP addresses:");
    let ifaces_vec: Vec<Vec<String>> = interfaces
            .iter()
            .map(|(name, ip)| vec![name.clone(), ip.to_string()])
            .collect();
    let mut table = prettytable::Table::new();
    table.add_row(row![FYb => "Interface", "IP Address"]);
    for iface in ifaces_vec {
        table.add_row(row![iface[0], iface[1]]);
    }
    table.printstd();
}       

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            print_usage_and_exit();
            process::exit(1);
        }
    };
    
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        let mut buf: [u8; 1600] = [0u8; 1600];
        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos"
                )) && interface.is_up()
                    && !interface.is_broadcast()
                    && ((!interface.is_loopback() && interface.is_point_to_point())
                        || interface.is_loopback())
                {
                    if interface.is_loopback() {
                        // The pnet code for BPF loopback adds a zero'd out Ethernet header
                        payload_offset = 14;
                    } else {
                        // Maybe is TUN interface
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let version = Ipv4Packet::new(&packet[payload_offset..])
                            .unwrap()
                            .get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable());
                            continue;
                        } else if version == 6 {
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap());
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}