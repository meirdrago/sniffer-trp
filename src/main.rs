
extern crate pnet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
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
use std::thread;
use std::sync::mpsc::{channel, Sender};

mod rtp_packet;
mod rtp_stats;
use crate::rtp_packet::{InterleaveTcpRtp, RtpPacket};


type PacketParams = (
    u8,     // protocol: u8, 1 = UDP or 2 = TCP
    IpAddr, // source_ip: IpAddr,
    u16,    // source_port: u16, 
    u16,    // sequence_number: u16,
    usize,  // payload_size: usize,
    u8,     // payload_type: u8,
);   
        

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


fn handle_udp_packet(source: IpAddr, _destination: IpAddr, packet: &[u8], ttx: &Sender<PacketParams>) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        if let Some(rtp) = RtpPacket::new(&packet[8..]){ // UDP header is 8 bytes
            //println!("[udp]: {}:{} -> {}:{}", source, udp.get_source(), _destination, udp.get_destination());  
            //println!("{:?}", rtp.header);
            if let Err(e) = ttx.send((
                1,
                source,
                udp.get_source(),
                rtp.header.sequence_number,
                rtp.header.payload_bytes,
                rtp.header.payload_type,
            )) {
                eprintln!("Error sending packet params: {}", e);
            }
        }
    }
}

fn handle_tcp_packet(source: IpAddr, _destination: IpAddr, packet: &[u8], ttx: &Sender<PacketParams>) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp { 
        let mut payload = tcp.payload();
        //let mut interleave_seq = 0;

        loop{
            if let Some(interleave) = InterleaveTcpRtp::parse(payload) {
                //interleave_seq += 1;
                //println!("[{}]  channel: {}, packet_len: {}, payload_len: {}, has_next: {}", 
                //    interleave_seq, interleave.channel, packet.len(), interleave.payload_len, interleave.next.is_some());
                if let Some(rtp) = RtpPacket::new(&interleave.payload) {
                    if let Err(e) = ttx.send((
                        2,
                        source,
                        tcp.get_source(),
                        rtp.header.sequence_number,
                        rtp.header.payload_bytes,
                        rtp.header.payload_type,
                    )) {
                        eprintln!("Error sending packet params: {}", e);
                    }
                    //println!("seq: {}, len: {}, pt: {}", rtp.header.sequence_number, rtp.header.payload_bytes, rtp.header.payload_type);
                }
                if let Some(next_payload) = interleave.next {
                    payload = next_payload;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    } 
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    ttx: &Sender<PacketParams>,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(source, destination, packet, ttx)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(source, destination, packet, ttx)
        }
        
        _ => {}
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, ttx: &Sender<PacketParams>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            ttx,
        );
    }
}


fn handle_ethernet_frame(interface: &NetworkInterface, ethernet: &EthernetPacket, ttx: &Sender<PacketParams>) {
    let _interface_name = &interface.name[..];
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, ttx),
        _ => {}
    }
}

fn print_usage_and_exit() {
    let interfaces = get_interface_ips();
    writeln!(io::stderr(), "USAGE: sniff-rtp <NETWORK INTERFACE> [FILERED IPS (comma separated)]").unwrap();
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
    
    let filter_ips: Vec<IpAddr> = match env::args().nth(2) {
        Some(ips_str) => {
            ips_str
                .split(',')
                .filter_map(|ip_str| match ip_str.parse::<IpAddr>() {
                    Ok(ip) => Some(ip),
                    Err(_) => {
                        eprintln!("Invalid IP address provided for filtering: {}", ip_str);
                        process::exit(1);
                    }
                })
                .collect()
        },
        None => Vec::new(),
    };
    

    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| {
            println!("No such network interface: {}", iface_name);
            print_usage_and_exit();
            process::exit(1);
        });


    // Create a channel to send on
    let (ttx, rrx) = channel::<PacketParams>();

    thread::spawn(move || {
        let mut rtp_stats = rtp_stats::RtpStats::new();
        let mut ts = chrono::Utc::now();
        loop {
            match rrx.recv() {
                Ok((protocol, source_ip, source_port, sequence_number, payload_size, payload_type)) => {
                    if filter_ips.len() > 0 && !filter_ips.contains(&source_ip) {
                        continue;
                    }
                    rtp_stats.update_stats(
                        protocol,
                        source_ip,
                        source_port,
                        sequence_number,
                        payload_size,
                        payload_type,
                    );
                    let now = chrono::Utc::now();
                    if (now - ts).num_seconds() >= 3 {
                        ts = now;
                        rtp_stats.print();
                    }

                    // delete old entries every 30 seconds
                    rtp_stats.clean_old_entries(30);
                }
                Err(e) => {
                    eprintln!("Error receiving packet params: {}", e);
                }
            }
        }
    });

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
                            handle_ethernet_frame(&interface, &fake_ethernet_frame.to_immutable(), &ttx);
                            continue;
                        } else if version == 6 {
                            continue;
                        }
                    }
                }
                handle_ethernet_frame(&interface, &EthernetPacket::new(packet).unwrap(), &ttx);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}