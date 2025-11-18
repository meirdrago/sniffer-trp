
#[derive(Debug, Clone)]
pub struct RtpInfo {
    pub protocol: u8, // 1 = UDP or 2 = TCP
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub mut last_sequence: u16,
    pub mut packet_count: u64,
    pub mut payload_bytes: u64,
    pub mut missed_packets: u64,
}

pub struct RtpStats {
    pub db: HashMap<u64, RtpInfo>,
}

Impl RtpStats {
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
        });

        // Update stats
        if sequence_number - entry.last_sequence > 1 {
            entry.missed_packets += (sequence_number - entry.last_sequence - 1) as u64;
        }
        entry.last_sequence = sequence_number;
        entry.packet_count += 1;
        entry.payload_bytes += payload_size as u64;
    }

    pub fn print_and_empty(&mut self) {
        use prettytable::{Table, row, cell};

        let mut table = Table::new();
        table.add_row(row!["Protocol", "Source IP", "Source Port", "Packets", "Payload Bytes", "Missed Packets"]);

        for (_key, info) in self.db.iter() {
            let protocol_str = match info.protocol {
                1 => "UDP",
                2 => "TCP",
                _ => "Unknown",
            };
            table.add_row(row![
                protocol_str,
                info.source_ip,
                info.source_port,
                info.packet_count,
                info.payload_bytes,
                info.missed_packets
            ]);
        }

        // Clear terminal and print table
        print!("{}{}", CLEAR_CODE, MOVE_TO_TOP_LEFT);
        table.printstd();

        // Clear stats after printing
        self.db.clear();
    }
}

