
use std::net::IpAddr;
use std::collections::HashMap;
use std::io::{self, Write};
use chrono::prelude::*;
use prettytable::{Table, Row, Cell};

const CLEAR_SCREEN_AND_MOVE_CURSOR: &str = "\x1bc";


#[derive(Debug, Clone)]
pub struct RtpInfo {
    pub protocol: u8, // 1 = UDP or 2 = TCP
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub last_sequence: u16,
    pub packet_count: u64,
    pub payload_bytes: u64,
    pub payload_type: u8,
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
        payload_type: u8,
        source_ip: &IpAddr,
        source_port: u16,
    ) -> u64 {
        let ip_numeric = match source_ip {
            IpAddr::V4(ipv4) => u32::from_be_bytes(ipv4.octets()) as u64,
            IpAddr::V6(_) => 0, // no ipv6 support for now
        };
        (payload_type as u64) << 48 | (ip_numeric << 16) | (source_port as u64)
    }

    pub fn update_stats(
        &mut self,
        protocol: u8,
        source_ip: IpAddr,
        source_port: u16,
        sequence_number: u16,
        payload_size: usize,
        payload_type: u8,
    ) {
        let key = RtpStats::create_key(payload_type, &source_ip, source_port);
        let entry = self.db.entry(key).or_insert(RtpInfo {
            protocol,
            source_ip: source_ip.clone(),
            source_port,
            last_sequence: sequence_number,
            packet_count: 0,
            payload_bytes: 0,
            payload_type: payload_type,
            missed_packets: 0,
            timestamp: Utc::now(),
        });

        // Update stats
        let seq_diff: i64 = sequence_number as i64 - entry.last_sequence as i64;
        if seq_diff < -1000 { // new sequence counter wrapped around
            entry.last_sequence = sequence_number;
           
        } else if seq_diff > 1 {
            println!("Missed {} packets from {}:{}", seq_diff - 1, source_ip, source_port);
            entry.missed_packets += (seq_diff - 1) as u64;
        }
        entry.last_sequence = sequence_number;
        entry.packet_count += 1;
        entry.payload_bytes += payload_size as u64;
        entry.timestamp = Utc::now();
    }

    pub fn print(&mut self) {
        return;
        let mut sorted_records: Vec<RtpInfo> = self.db.values().cloned().collect();
        sorted_records.sort_by(|a, b| {
            a.source_port.cmp(&b.source_port)
        });

        let mut table = Table::new();
        table.add_row(Row::new(vec![
            Cell::new("Protocol").style_spec("FYb"),
            Cell::new("Source IP").style_spec("FYb"),
            Cell::new("Source Port").style_spec("FYb"),
            Cell::new("Packets").style_spec("FYb"),
            Cell::new("Payload Bytes").style_spec("FYb"),
            Cell::new("PT").style_spec("FYb"),
            Cell::new("Missed Packets").style_spec("FYb"),
            Cell::new("Packet Time").style_spec("FYb"),
            Cell::new("Last Seq").style_spec("FYb"),  
        ]));

        for info in sorted_records {
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
                Cell::new(&info.payload_type.to_string()),
                Cell::new(&info.missed_packets.to_string()),
                Cell::new(&info.timestamp.format("%Y-%m-%d %H:%M:%S").to_string()),
                Cell::new(&info.last_sequence.to_string()),
            ]));
        }

        print!("{}", CLEAR_SCREEN_AND_MOVE_CURSOR);
        io::stdout().flush().expect("Could not flush stdout");
        table.printstd();
    }

    pub fn clean_old_entries(&mut self, secs: usize) {
        let now = Utc::now();
        self.db.retain(|_, info| {
            (now - info.timestamp).num_seconds() < secs as i64
        });
    }
}

