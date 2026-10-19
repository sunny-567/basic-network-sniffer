# Basic Network Sniffer

A Python and Scapy command-line tool for authorized network troubleshooting and
cybersecurity education. It reports packet metadata: timestamp, source and
destination IP addresses, protocol, TCP/UDP ports when available, and packet
length. It can export those fields to CSV or read an authorized PCAP file.

## Security and authorized use

Use live capture only on an interface and network you own or are explicitly
authorized to monitor. This project reports metadata only; it does not display
or export application payload contents. IP addresses and timestamps may still
be sensitive. Do not publish them without permission.

## Features

- IPv4 and IPv6 source/destination addresses.
- TCP, UDP, ICMP, and ICMPv6 protocol labels.
- Bounded capture using packet-count and timeout limits.
- Terminal table and protocol totals.
- Fixed metadata-only CSV export.
- Optional offline PCAP reading.
- Unit tests based on synthetic packets and mocks.

## Project structure

```text
basic-network-sniffer/
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── capture.py
│   ├── parser.py
│   └── export.py
├── tests/
├── scripts/
├── samples/
├── output/
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

## Windows setup (PowerShell)

Python 3.11 is used in these commands. From the project root:

```powershell
py -3.11 --version
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

If Python 3.11 is not installed, use a supported Python version available on
your computer and create the environment with that version's `py` command.

## Run tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Show help

```powershell
.\.venv\Scripts\python.exe -m src.main --help
```

## Generate synthetic demonstration data

```powershell
.\.venv\Scripts\python.exe .\scripts\generate_synthetic_sample.py --output .\output\synthetic-demo.csv
Invoke-Item .\output\synthetic-demo.csv
```

The generated CSV is synthetic, not a real network capture.

## List interfaces for an authorized live capture

```powershell
.\.venv\Scripts\python.exe -c "from scapy.all import get_if_list; print('\\n'.join(get_if_list()))"
```

Live capture on Windows may require an approved Npcap installation and
permitted privileges. Do not bypass operating-system or organizational controls.

## Run a short live capture

Only after confirming authorization and the exact interface name:

```powershell
.\.venv\Scripts\python.exe -m src.main --count 25 --timeout 10 --interface "Wi-Fi" --output .\output\lab-capture.csv
```

Replace `Wi-Fi` with an exact interface name returned by the interface-list
command. Choose a different output filename if the destination already exists.

## Read an authorized PCAP file

```powershell
.\.venv\Scripts\python.exe -m src.main --read-pcap .\samples\authorized-lab.pcap --count 100 --timeout 30 --output .\output\pcap-metadata.csv
```

The example PCAP path is a placeholder; no PCAP file is bundled.
