mod scanner;
mod threads;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    ip: String,

    #[arg(short, long, default_value_t = 1)]
    start_port: u16,

    #[arg(short, long, default_value_t = 1024)]
    end_port: u16,
}

fn main() {
    let args = Cli::parse();
    println!("Starting scan on IP: {} from port {} to {}", args.ip, args.start_port, args.end_port);

    threads::run_syn_scan(&args.ip, args.start_port, args.end_port);
}
