// TCP State Transition Diagram (RFC 793)
// =====================================
//
// This diagram illustrates the complete TCP finite state machine showing
// all possible state transitions during connection establishment, data
// transfer, and connection termination phases.
//
// Legend:
//   - Rectangular boxes represent TCP states
//   - Arrows show state transitions
//   - Text above arrows shows triggering events
//   - Text below arrows shows resulting actions
//   - 'x' indicates the transition completes/is consumed
//
//                     +---------+ ---------\      active OPEN
//                               |  CLOSED |            \    -----------
//                               +---------+<---------\   \   create TCB
//                                 |     ^              \   \  snd SYN
//                    passive OPEN |     |   CLOSE        \   \
//                    ------------ |     | ----------       \   \
//                     create TCB  |     | delete TCB         \   \
//                                 V     |                      \   \
//                               +---------+            CLOSE    |    \
//                               |  LISTEN |          ---------- |     |
//                               +---------+          delete TCB |     |
//                    rcv SYN      |     |     SEND              |     |
//                   -----------   |     |    -------            |     V
//  +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//  |         |<-----------------           ------------------>|         |
//  |   SYN   |                    rcv SYN                     |   SYN   |
//  |   RCVD  |<-----------------------------------------------|   SENT  |
//  |         |                    snd ACK                     |         |
//  |         |------------------           -------------------|         |
//  +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//    |           --------------   |     |   -----------
//    |                  x         |     |     snd ACK
//    |                            V     V
//    |  CLOSE                   +---------+
//    | -------                  |  ESTAB  |
//    | snd FIN                  +---------+
//    |                   CLOSE    |     |    rcv FIN
//    V                  -------   |     |    -------
//  +---------+          snd FIN  /       \   snd ACK          +---------+
//  |  FIN    |<-----------------           ------------------>|  CLOSE  |
//  | WAIT-1  |------------------                              |   WAIT  |
//  +---------+          rcv FIN  \                            +---------+
//    | rcv ACK of FIN   -------   |                            CLOSE  |
//    | --------------   snd ACK   |                           ------- |
//    V        x                   V                           snd FIN V
//  +---------+                  +---------+                   +---------+
//  |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
//  +---------+                  +---------+                   +---------+
//    |                rcv ACK of FIN |                 rcv ACK of FIN |
//    |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
//    |  -------              x       V    ------------        x       V
//     \ snd ACK                 +---------+delete TCB         +---------+
//      ------------------------>|TIME WAIT|------------------>| CLOSED  |
//                               +---------+                   +---------+
//
// State Descriptions:
// ------------------
// CLOSED      - No connection exists
// LISTEN      - Server waiting for connection requests  
// SYN-SENT    - Client has sent SYN, waiting for SYN-ACK
// SYN-RCVD    - Server received SYN, sent SYN-ACK, waiting for ACK
// ESTABLISHED - Connection is open, data transfer can occur
// FIN-WAIT-1  - Local application closed, sent FIN, waiting for ACK
// FIN-WAIT-2  - Received ACK of FIN, waiting for remote FIN
// CLOSE-WAIT  - Remote sent FIN, local ACKed, waiting for local close
// CLOSING     - Both sides closing simultaneously
// LAST-ACK    - Remote closed, local closing, waiting for final ACK
// TIME-WAIT   - Waiting 2MSL to ensure remote received final ACK
//
// Key Transitions:
// - Three-way handshake: CLOSED -> SYN-SENT -> ESTABLISHED (client)
// - Three-way handshake: CLOSED -> LISTEN -> SYN-RCVD -> ESTABLISHED (server)
// - Four-way handshake: ESTABLISHED -> FIN-WAIT-1 -> FIN-WAIT-2 -> TIME-WAIT -> CLOSED
// - Simultaneous open: CLOSED -> SYN-SENT -> SYN-RCVD -> ESTABLISHED
// - Simultaneous close: ESTABLISHED -> FIN-WAIT-1 -> CLOSING -> TIME-WAIT -> CLOSED



// Each state represents a specific stage in the TCP connection
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    // Keeps track of various sequence numbers (packet ordering label) for data we've sent
    send: SendSequenceSpace,
    // Keeps track of sequence numbers (packet ordering label) for data we're receiving
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

struct SendSequenceSpace {
    // SND.UNA: Oldest sequence number not yet acknowledged by the receiver
    una: u32,
    // SND.NXT: Next sequence number to be used for new data for transmission
    nxt: u32,
    // SND.WND: Window Size or # of bytes allowed to be outstanding (unacknowledged)
    wnd: u16,
    // Indicates if the URG control bit is set -- if True, the sequence number in the urgent
    // pointer field is in
    up: bool,
    // Sequence number of the segment used for the last window update
    wl1: usize,
    // Acknowledgement number used for the last window update
    wl2: usize,
    // Initial Send Sequence number -- the first sequence number used when the connection was
    // established
    iss: u32,
}

struct RecvSequenceSpace {
    // RCV.NXT: Next expected sequence number that the receiver is expecting
    nxt: u32,
    // RCV.WND: The number of bytes that the receiver is willing to accept
    wnd: u16,
    // Indicates if the URG control bit is set on received data
    up: bool,
    // Initial Receive Sequence number: Sequence number of the first byte received
    irs: u32,
}


// Sets default TCP state to 'Listen'
impl Default for State {
    fn default() -> Self {
        State::Listen
    }
}

impl State {
    // Handle incoming TCP packets
    pub fn on_packet<'a>(
        &mut self, 
        ipv4_header: etherparse::Ipv4HeaderSlice<'a>, // Parsed IPv4 Header
        tcp_header: etherparse::TcpHeaderSlice<'a>, // Parsed TCP Header
        tcp_payload: &'a [u8], // Reference to payload with lifetime a
    ) {
        // Log metadata of packet
        eprintln!(
            "{}:{} -> {}:{} {}b of TCP",
            ipv4_header.source_addr(),
            tcp_header.source_port(),
            ipv4_header.destination_addr(),
            tcp_header.destination_port(),
            tcp_payload.len()
        );
    }
}


impl Connection {
    // Handles incoming TCP packet for establishing a connection
    // If incoming packet is a SYN, it prepares and sends a SYN-ACK packet in response.
    // Otherwise, the packet is ignored. 
    //
    // Returns a new `Connection` in the `SynRcvd` state if the incoming packet was a SYN packet
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        ipv4_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        tcp_payload: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcp_header.syn() {
            // Ignore packets that aren't SYN packets
            return Ok(None);
        }
        let iss = 0;
        let wnd = 10;
        let mut connection = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: 1,
                wnd: wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                // Initialize receive sequence number to the incoming sequence number
                irs: tcp_header.sequence_number(),
                // Expect the next byte after the incoming sequence number
                nxt: tcp_header.sequence_number() + 1,
                // Use incoming packet's window size for our receive window
                wnd: tcph.window_size(),
                up: false,
            },

            // Prepare SYN-ACK packet in response to SYN packet
            tcp: etherparse::TcpHeader::New(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                wnd,
            ),
            ip: etherparse::Ipv4Header::new(
                syn_ack.header_len(),               // payload length
                64,                                 // Time-to-live
                etherparse::IpNumber::Tcp as u8,    // Protocol
                [                                   // Source
                    ip_header.destination()[0],
                    ip_header.destination()[1],
                    ip_header.destination()[2],
                    ip_header.destination()[3],
                ],
                [                                   // Destination
                    ip_header.source()[0],
                    ip_header.source()[1],
                    ip_header.source()[2],
                    ip_header.source()[3],
                ],
            )
        };

        connection.tcp.acknowledgement_number = c.recv.nxt;
        connection.tcp.syn = true;
        connection.tcp.ack = true;

        connection.ip.set_payload_len(c.tcp.header_len() as usize + 0);

        // Calculate and set the checksum for the SYN-ACK packet
        connection.tcp.checksum = connection.tcp
            .calc_checksum_ipv4(&connection.ip, &[]) // Empty payload: Empty array
            .expect("Failed to compute checksum");

        // Write out TCP and IP headers to a buffer to be sent
        // Kinda confusing variable shadowing pattern here, is a common Rust idiom:
        let unwritten: usize = {
            let mut unwritten = &mut buf[..]; // (type: &mut [u8]) - shadows outer `unwritten`
            ip.write(&mut unwritten);         // Writes to inner unwritten
            syn_ack.write(&mut unwritten)     // Writes to inner unwritten
            unwritten.len()                   // Returns length of inner unwritten, assign to outer
        };

        // Send the SYN-ACK packet
        nic.send(&buf[..unwritten])?;
        Ok(Some(connection))
    }

    // Function to handle incoming packets once a connection is established
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        ipv4_header: etherparse::Ipv4HeaderSlice<'a>,
        tcp_header: etherparse::TcpHeaderSlice<'a>,
        tcp_payload: &'a [u8], 
    ) -> io::Result<()> {
        // Process incoming packet based on its flags and current connection state
        Ok(())
    }
}
