
use std::net::IpAddr;
use std::collections::HashMap;
use chrono::prelude::*;
use prettytable::{Table, Row, Cell};

const CLEAR_CODE: &str = "\x1B[2J"; 
const MOVE_TO_TOP_LEFT: &str = "\x1B[H";


#[derive(Debug, Clone)]
pub struct RtpInfo {
    pub protocol: u8, // 1 = UDP or 2 = TCP
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub last_sequence: u16,
    pub packet_count: u64,
    pub payload_bytes: u64,
    pub missed_packets: u64,
    pub timestamp: DateTime<Utc>,
}

pub struct RtpStats {
    pub db: HashMap<u64, RtpInfo>,
}

impl RtpStats {
    pub fn new() -> RtpStats {
        RtpStats {
            db: HashMap::new(),
        }
    }

    fn create_key(
        protocol: u8,
        source_ip: &IpAddr,
        source_port: u16,
    ) -> u64 {
        let ip_numeric = match source_ip {
            IpAddr::V4(ipv4) => u32::from_be_bytes(ipv4.octets()) as u64,
            IpAddr::V6(_) => 0, // no ipv6 support for now
        };
        (protocol as u64) << 48 | (ip_numeric << 16) | (source_port as u64)
    }

    pub fn update_stats(
        &mut self,
        protocol: u8,
        source_ip: IpAddr,
        source_port: u16,
        sequence_number: u16,
        payload_size: usize,
    ) {
        let key = RtpStats::create_key(protocol, &source_ip, source_port);
        let entry = self.db.entry(key).or_insert(RtpInfo {
            protocol,
            source_ip: source_ip.clone(),
            source_port,
            last_sequence: sequence_number,
            packet_count: 0,
            payload_bytes: 0,
            missed_packets: 0,
            timestamp: Utc::now(),
        });

        // Update stats
        if sequence_number - entry.last_sequence > 1 {
            entry.missed_packets += (sequence_number - entry.last_sequence - 1) as u64;
        }
        entry.last_sequence = sequence_number;
        entry.packet_count += 1;
        entry.payload_bytes += payload_size as u64;
    }

    pub fn print(&mut self) {


        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Protocol").style_spec("FYb"),
            Cell::new("Source IP").style_spec("FYb"),
            Cell::new("Source Port").style_spec("FYb"),
            Cell::new("Packets").style_spec("FYb"),
            Cell::new("Payload Bytes").style_spec("FYb"),
            Cell::new("Missed Packets").style_spec("FYb"),
            Cell::new("Last Packet Time").style_spec("FYb"),  
        ]));

        for (_key, info) in self.db.iter() {
            let protocol_str = match info.protocol {
                1 => "UDP",
                2 => "TCP",
                _ => "Unknown",
            };
            table.add_row(Row::new(vec![
                Cell::new(protocol_str),
                Cell::new(&info.source_ip.to_string()),
                Cell::new(&info.source_port.to_string()),
                Cell::new(&info.packet_count.to_string()),
                Cell::new(&info.payload_bytes.to_string()),
                Cell::new(&info.missed_packets.to_string()),
                Cell::new(&info.timestamp.format("%Y-%m-%d %H:%M:%S").to_string()),
            ]));
        }

        // Clear terminal and print table
        print!("{}{}", CLEAR_CODE, MOVE_TO_TOP_LEFT);
        table.printstd();
    }
}

