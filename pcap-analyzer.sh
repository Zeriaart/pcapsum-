#!/bin/sh
DIR="$(dirname "$(readlink -f "$0")")"
python3 "$DIR/pcap-analyzer.py" "$@"
