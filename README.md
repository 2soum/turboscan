
# TurboScan

**TurboScan** is an ultra-fast, multi-threaded port scanner built in Rust. It is designed to be simple, efficient, and accessible to all users. The tool performs SYN scans to quickly detect open ports on a target system.

## Features

- **Multi-threaded**: Utilizes multiple threads for faster scanning.
- **SYN Scanning**: Sends TCP SYN packets to detect open ports.
- **Efficient**: Optimized for speed and performance, designed for high network efficiency.
- **Simple CLI**: Easily scannable using simple command-line arguments.

## Usage

TurboScan can be run directly from the command line. Below is an example of how to use the tool:

```bash
sudo turboscan -t <target-ip> -p <port-range>
```

### Arguments:

- `-t`, `--target`: The target IP address or domain to scan.
- `-p`, `--ports`: The range of ports to scan, e.g., `1-1024`.

Example:

```bash
sudo turboscan -t 192.168.1.1 -p 1-65535
```

This will scan all ports from 1 to 65535 on the IP `192.168.1.1`.

### Requirements

- **Rust**: Install Rust by following the instructions at https://www.rust-lang.org/tools/install
- **Administrator Access**: Running the tool requires administrator privileges (e.g., `sudo` on Linux).
