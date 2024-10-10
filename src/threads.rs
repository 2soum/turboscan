use rayon::prelude::*;
use crate::scanner;

pub fn run_syn_scan(ip: &str, start_port: u16, end_port: u16) {
    println!("Running scan from port {} to {}", start_port, end_port);

    let results: Vec<_> = (start_port..=end_port)
        .into_par_iter()  // Rayon for parallel processing
        .map(|port| {
            let result = scanner::syn_scan(ip, port);
            (port, result)
        })
        .collect();

    // Display resu
    for (port, status) in results {
        println!("Port {}: {}", port, status);
    }
}
