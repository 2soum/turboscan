use rand::random;
use pnet::packet::tcp::{TcpFlags, MutableTcpPacket, TcpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType::Layer3, ipv4_packet_iter};
use pnet::packet::ipv4::MutableIpv4Packet; // Pour gérer les paquets IPv4
use std::net::{Ipv4Addr, IpAddr, ToSocketAddrs};
use std::time::Duration;
use std::net::UdpSocket;

pub fn syn_scan(ip_or_domain: &str, port: u16) -> String {
    println!("Starting SYN scan for {} on port {}", ip_or_domain, port);

    // Resolve destination IP
    let destination_ip = match resolve_ip(ip_or_domain) {
        Some(ip) => ip,
        None => {
            eprintln!("Unable to resolve domain or IP: {}", ip_or_domain);
            return "Invalid domain or IP".to_string();
        }
    };

    println!("Resolved IP: {}", destination_ip);
    // Get the local source IP address
    let source_ip = match get_local_ip() {
        Some(ip) => ip,
        None => {
            eprintln!("Unable to determine local IP address.");
            return "Failed to get local IP".to_string();
        }
    };
    println!("Source IP: {}", source_ip);

    // Setup transport channel
    let protocol = Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            eprintln!("Failed to create transport channel: {}", e);
            return "Transport channel error".to_string();
        }
    };

    // Build TCP SYN packet
    let mut tcp_buffer = [0u8; 20]; // Fixed size for TCP header
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
        let source_port: u16 = random::<u16>(); // Random source port
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(port);
        tcp_packet.set_sequence(1);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(5); // Data offset: 5 (no options)
        println!("Using source port: {}", source_port); // Debug: Print the source port
    }

    // Calculate checksum
    let tcp_length = tcp_buffer.len();
    let checksum = pnet::util::ipv4_checksum(
        &tcp_buffer[..],
        tcp_length,
        &[], // No payload
        &source_ip,
        &destination_ip,
        IpNextHeaderProtocols::Tcp,
    );
    println!("Calculated TCP checksum: {}", checksum); // Debug: Print the checksum

    // Apply the checksum
    {
        let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
        tcp_packet.set_checksum(checksum);
    }

    // Build the IP header (IPv4)
    let mut ip_buffer = [0u8; 40]; // Buffer size for IP + TCP headers
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(40);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_packet.set_source(source_ip);
    ip_packet.set_destination(destination_ip);
    ip_packet.set_payload(&tcp_buffer); // Attach the TCP packet

    // Send the IP packet with TCP SYN encapsulated
    match tx.send_to(ip_packet, IpAddr::V4(destination_ip)) {
        Ok(_) => println!("Successfully sent SYN packet to {}:{}", destination_ip, port),
        Err(e) => {
            eprintln!("Failed to send packet: {}", e);
            return "Failed to send packet".to_string();
        }
    }

    // Increase timeout to 15 seconds
    let mut iter = ipv4_packet_iter(&mut rx);
    let timeout = Duration::from_secs(15);
    while let Ok(Some((packet, _))) = iter.next_with_timeout(timeout) {
        if packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
            if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                println!("Received TCP packet: {:?}", tcp_packet); // Debugging print to see the packet content

                // Check if the packet is from the expected source and port
                if tcp_packet.get_source() == port && tcp_packet.get_destination() == 12345 {
                    
                    let flags = tcp_packet.get_flags();
                    
                    // SYN-ACK means the port is open
                    if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                        return "Open".to_string();
                    } 
                    
                    // RST means the port is closed
                    else if flags & TcpFlags::RST > 0 {
                        return "Closed".to_string();
                    }
                    
                    // ACK without SYN could indicate filtered or established states
                    else if flags & TcpFlags::ACK > 0 {
                        println!("ACK received without SYN-ACK, possibly a filtered or established connection.");
                        return "Filtered or established".to_string();
                    }
                }
            }
        }
    }

    println!("No response received for port {}", port);
    "Filtered or no response".to_string()

}

// Function to get the local IP address by creating a dummy UDP connection
fn get_local_ip() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    if let IpAddr::V4(local_ip) = local_addr.ip() {
        Some(local_ip)
    } else {
        None
    }
}

// Function to resolve domain name or IP address
fn resolve_ip(domain: &str) -> Option<Ipv4Addr> {
    let addr = format!("{}:0", domain);
    let mut iter = addr.to_socket_addrs().ok()?;
    iter.find_map(|addr| {
        if let IpAddr::V4(ipv4) = addr.ip() {
            Some(ipv4)
        } else {
            None
        }
    })
}
