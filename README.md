# pcapsum

A fast, CTF-ready PCAP analysis tool that wraps tshark to deliver 
deep traffic summaries, credential extraction, and stream inspection 
— all in a clean terminal report.

## What it does

Drop a .pcap file in, get a structured report out. No Wireshark GUI, 
no manual filters — just run it and read the findings.

- Protocol hierarchy & traffic statistics
- TCP stream reconstruction
- HTTP traffic breakdown
- FTP/cleartext credential detection
- IP/TCP/UDP conversation summaries
- CTF threat scoring
- JSON output mode

## Usage

pcapsum file.pcap              # Full analysis
pcapsum -q file.pcap           # Quick mode  
pcapsum -f file.pcap           # Flag hunt only
pcapsum -s 0 file.pcap         # Follow TCP stream 0
pcapsum -j file.pcap > out.json

## Requirements

- Python 3
- tshark (Wireshark CLI)

## Install

git clone https://github.com/Zeriaart/pcapsum-.git
cd pcapsum-
chmod +x install.sh
./install.sh
