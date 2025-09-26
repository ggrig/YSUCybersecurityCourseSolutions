# Packet Summary Tool (Option A)

This tool (`packet_summary.py`) processes a PCAP/PCAPNG file and generates two outputs:

1. **summary.csv** – A per-packet CSV log with timestamp, IP/ports, protocol, flags, and DNS details  
2. **report.txt** – An aggregate summary including TCP flag counts, unique flows, DNS statistics, top queried domains, and DNS RTTs

---

## Requirements

- Python 3.8+  
- Install Scapy:

```bash
pip install scapy
```

---

## Usage

```bash
python packet_summary.py --pcap capture.pcap --outdir output/
```

### Options

- `--pcap <file>` (required) → Input PCAP/PCAPNG file  
- `--outdir <dir>` (default: `output`) → Directory to save CSV and report  
- `--only-dns` → Process only DNS packets  
- `--only-tcp` → Process only TCP packets  
- `--max-packets N` → Limit number of packets processed (for testing)  

---

## Example Run

```bash
python packet_summary.py --pcap traffic.pcap --outdir results/
```

This creates:

- `results/summary.csv`  
- `results/report.txt`  

---

## Outputs

### summary.csv
Each row contains:

- Timestamp (UTC ISO format)  
- IP version (4 or 6)  
- Source/destination IP + ports  
- Protocol (TCP/UDP)  
- Packet length  
- Info (flags or DNS details)

### report.txt
Includes:

- Total packets processed  
- Protocol counts  
- TCP flag counts (SYN, SYN-ACK, ACK, FIN, RST)  
- Completed TCP handshakes detected  
- DNS queries, responses, NXDOMAINs  
- Top 5 queried domains  
- Average DNS RTT (ms)

---

## Suggested Student Deliverables

- `packet_summary.py` script  
- `summary.csv` + `report.txt` outputs  
- A short (1–2 page) write-up explaining observations in terms of **TCP/IP layers** and **DNS concepts**  

---

## Notes

- Capture your own packets with Wireshark or tcpdump and test them.  
- Use filters like `dns` or `tcp.port==80` in Wireshark to compare against script results.  
- Remember to capture only on networks you own or have permission to monitor.
