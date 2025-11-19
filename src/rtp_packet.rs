// Simple RTP packet header and packet parser utilities

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc_list: Vec<u32>,
    pub payload_bytes: usize,
}

impl RtpHeader {
    pub fn parse(packet: &[u8]) -> Option<RtpHeader> {
        if packet.len() < 12 {
            return None;
        }
        let b0 = packet[0];
        let b1 = packet[1];
        let version = (b0 >> 6) & 0x03;
        if version != 2 {
            return None;
        }
        let padding = ((b0 >> 5) & 0x01) != 0;
        let extension = ((b0 >> 4) & 0x01) != 0;
        let csrc_count = b0 & 0x0f;
        let marker = (b1 >> 7) != 0;
        let payload_type = b1 & 0x7f;
        let sequence_number = u16::from_be_bytes([packet[2], packet[3]]);
        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let ssrc = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
        if payload_type != 96 {
            return None; // Only dynamic payload 96 are considered RTP here
        }

        let mut offset: usize = 12;
        let mut csrc_list = Vec::new();
        for _ in 0..csrc_count {
            if packet.len() < offset + 4 {
                return None;
            }
            let c = u32::from_be_bytes([
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ]);
            csrc_list.push(c);
            offset += 4;
        }
        let payload_bytes = packet.len() - offset;

        Some(
            RtpHeader {
                version,
                padding,
                extension,
                csrc_count,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrc_list,
                payload_bytes,
            }
        )
    }
}

#[derive(Debug)]
pub struct RtpPacket<'a> {
    pub header: RtpHeader,
    
    #[allow(dead_code)]
    pub payload: &'a [u8],
}

impl<'a> RtpPacket<'a> {
    pub fn new(packet: &'a [u8]) -> Option<RtpPacket<'a>> {
        if let Some(header) = RtpHeader::parse(packet) {
            let offset = packet.len() - header.payload_bytes;
            if offset <= 0 {
                return None;
            }
            let payload = &packet[offset..];
            Some(RtpPacket { header, payload })
        } else {
            None
        }
    }
}
