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
