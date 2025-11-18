
#[derive(Debug, Clone)]
pub struct RtpInfo {
    pub protocol: u8, // 1 = UDP or 2 = TCP
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub packet_count: u64,
    pub payload_count: u64,
    pub missed_packets: u64,
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
}

