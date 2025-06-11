use std::io;
use std::collections::HashMap;
use std::net::Ipv4Addr;
mod tcp;

// Connection Quad: Unique Identifier for TCP connections
// Used as a key in TCB (Transmission Control Block) Hashmap
// 4-tuple of source IP, source port, destination IP, and destination port
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad{
    source_socket: (Ipv4Addr, u16),
    destination_socket: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    // Initialize a HashMap to store TCP connection states against their connection Quad tuple
    let mut connections: HashMap<Quad, tcp::State> = Default::default();

    // Create a new virtual NIC named "tun0" in TUN mode.
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;

    // Define a buffer of size 1504 bytes (maximum Ethernet frame size without CRC) to store received data.
    let mut buf = [0u8; 1504];

    // Main loop to continuously receive data from the interface.
    loop {
        // Receive data from the TUN interface and store the number of bytes received in `nbytes`.
        let nbytes = nic.recv(&mut buf[..])?;

        // TUN/TAP frame format (source: https://www.kernel.org/doc/Documentation/networking/tuntap.txt sec. 3.2):
        // [Note: big endian ordering]
        // First 2 bytes: Flags
        // Second 2 bytes: Protocol
        // Remainder: Raw protocol frame
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        if protocol != 0x0800 { 
            // Skip if protocol neq IPv4 (https://en.wikipedia.org/wiki/EtherType#Values)
            continue;
        }


        // Try to parse IPv4 header from raw protocol frame buffer slice:
        //
        // IPv4 Header Format
        // ====================
        // Offsets | Octet |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
        // ---------|-------|------------------------------------------------------------------------------------------------
        //    0     |   0   | Version |  IHL  |    DSCP   |ECN|                    Total Length                           |
        //    4     |  32   |                Identification                |  Flags  |         Fragment Offset         |
        //    8     |  64   |    Time To Live   |    Protocol    |                 Header Checksum                      |
        //   12     |  96   |                                    Source IP Address                                       |
        //   16     | 128   |                                 Destination IP Address                                    |
        //   20     | 160   |                                                                                            |
        //    :     |   :   |                              Options (if IHL > 5)                                       |
        //   56     | 448   |                                                                                            |
        // 
                
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            // If parsing is successful, proceed with parsed packet
            Ok(ipv4_header) => {
                // extract source IP address from parsed packet
                let source_addr = ipv4_header.source_addr();
                // extract destination IP address
                let destination_addr = ipv4_header.destination_addr();
                // extract protocol number (TCP is typically 6 (0x06))
                let protocol = ipv4_header.protocol();

                if protocol != 0x06 {
                    // If packet is not a TCP packet, we skip it
                    continue;
                }

                // Try to parse TCP header from raw frame buffer slice
                // Adjust starting slice based on length of IPv4 header
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + p.slice().len()..]) {
                    // If parsing TCP Header is successful we can proceed
                    Ok(tcp_header) => {
                        let data_start_index = 4 + ipv4_header.slice().len() + tcp_header.slice().len();

                        // Check for corresponding existing entry in connection hashmap, create if none exists
                        match connections.entry(Quad{
                            src: (source_addr, tcp_header.source_port()),
                            dst: (destination_addr, tcp_header.destination_port()),
                        }) {
                            // Connection exists, print metadata about packet
                            Entry::Occupied(mut connection) => {
                                connection.get_mut().on_packet(&mut nic, ipv4_header, tcp_header, &buf[data_start_index..nbytes])?;
                            }
                            // Connection does not exist, try to create it
                            Entry::Vacant(entry) => {
                                if let Some(connection) = tcp::Connection::on_accept(&mut nic, ipv4_header, tcp_header, &buf[data_start_index..nbytes])? {
                                    entry.insert(connection);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("An error occurred while parsing TCP packet: {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("An error occurred while parsing IP packet: {:?}", e);
            }
        }
    }

    Ok(())
}

