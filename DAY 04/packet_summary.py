#!/usr/bin/env python3
"""
Option A — PCAP Packet Summary

Reads a PCAP/PCAPNG and produces:
  1) summary.csv  - per-packet rows
  2) report.txt   - aggregate statistics

Features:
  - TCP flag counts (SYN, SYN-ACK, ACK, FIN, RST)
  - Unique flow counting (direction-agnostic 5-tuple)
  - DNS stats: queries, responses, NXDOMAIN, unique domains, top 5
  - DNS RTTs (ms) by matching query/response on (txid, src, dst)
  - TCP 3-way handshake detection (per flow)
"""

import argparse
import csv
import os
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import rdpcap, DNS, IP, IPv6, TCP, UDP

# ------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------

def ts_iso(ts_float: float) -> str:
    """Convert a timestamp float to an ISO 8601 UTC string."""
    return datetime.utcfromtimestamp(ts_float).isoformat() + "Z"

def l3_addrs(pkt):
    """Extract L3 (IP/IPv6) addresses and packet length."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst, 4, int(pkt[IP].len) if hasattr(pkt[IP], "len") else len(pkt)
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst, 6, int(pkt[IPv6].plen) if hasattr(pkt[IPv6], "plen") else len(pkt)
    return None, None, None, len(pkt)

def l4_info(pkt):
    """Extract L4 protocol details: protocol, ports, TCP flags."""
    if TCP in pkt:
        flags = pkt[TCP].flags
        # Generate human-readable flag string (e.g., 'S', 'SA', 'FA')
        order = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                 ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80)]
        flag_str = "".join(ch for ch, bit in order if flags & bit)
        return "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport), flag_str
    if UDP in pkt:
        return "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport), ""
    return None, None, None, ""

def undirected_flow_key(proto, src, sport, dst, dport):
    """
    Create a direction-agnostic flow key (so A→B and B→A are the same).
    Returns a tuple: (proto, ((ip,port),(ip,port))) sorted.
    """
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        pair = (a, b)
    else:
        pair = (b, a)
    return (proto, pair)

def is_dns_query(pkt):
    return DNS in pkt and pkt[DNS].qr == 0

def is_dns_response(pkt):
    return DNS in pkt and pkt[DNS].qr == 1

# ------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="PCAP Packet Summary (Option A)")
    p.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    p.add_argument("--outdir", default="output", help="Output directory (default: output)")
    p.add_argument("--only-dns", action="store_true", help="Process only DNS packets")
    p.add_argument("--only-tcp", action="store_true", help="Process only TCP packets")
    p.add_argument("--max-packets", type=int, default=None, help="Limit number of packets (for testing)")
    return p.parse_args()

# ------------------------------------------------------------
# Main processing
# ------------------------------------------------------------

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # Load packets from PCAP file
    packets = rdpcap(args.pcap)
    if args.max_packets is not None:
        packets = packets[: args.max_packets]

    # Output file paths
    csv_path = os.path.join(args.outdir, "summary.csv")
    report_path = os.path.join(args.outdir, "report.txt")

    # Aggregation containers
    tcp_flag_counts = Counter()
    proto_counts = Counter()
    flow_set = set()                # track unique TCP/UDP flows
    dns_query_count = 0
    dns_resp_count = 0
    dns_nxdomain_count = 0
    dns_domains = Counter()
    dns_rtts_ms = []

    # For handshake detection:
    # Track state per direction-agnostic flow: SYN -> SYN/ACK -> ACK
    handshake_state = defaultdict(lambda: {"SYN": False, "SYNACK": False, "ACK": False})
    completed_handshakes = 0

    # For DNS RTTs: pending_queries[(txid, src, dst)] = ts
    pending_queries = {}

    # ------------------------------------------------------------
    # Per-packet processing (CSV output + aggregation)
    # ------------------------------------------------------------
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "ip_version",
            "src", "sport", "dst", "dport",
            "l4_proto", "length", "info"
        ])

        for pkt in packets:
            # Optional filters
            if args.only_dns and (DNS not in pkt):
                continue
            if args.only_tcp and (TCP not in pkt):
                continue

            ts = float(pkt.time)
            timestamp = ts_iso(ts)

            src, dst, ipver, l3_len = l3_addrs(pkt)
            proto, sport, dport, flags_str = l4_info(pkt)

            info_parts = []
            if proto == "TCP" and flags_str:
                info_parts.append(f"TCP flags={flags_str}")
            if DNS in pkt:
                d = pkt[DNS]
                if d.qr == 0 and d.qd is not None:
                    qname = d.qd.qname.decode(errors="ignore") if isinstance(d.qd.qname, bytes) else str(d.qd.qname)
                    info_parts.append(f"DNS Q: {qname}")
                elif d.qr == 1:
                    rcode = d.rcode
                    info_parts.append(f"DNS Resp rcode={rcode}")
                    if d.qd is not None:
                        qname = d.qd.qname.decode(errors="ignore") if isinstance(d.qd.qname, bytes) else str(d.qd.qname)
                        info_parts.append(f"Q={qname}")

            info = " | ".join(info_parts)

            # Write per-packet row
            writer.writerow([
                timestamp, ipver or "", src or "", sport or "",
                dst or "", dport or "", proto or "", l3_len, info
            ])

            # Aggregation
            if proto:
                proto_counts[proto] += 1

            if proto in ("TCP", "UDP") and src and dst and sport is not None and dport is not None:
                flow_set.add(undirected_flow_key(proto, src, sport, dst, dport))

            if proto == "TCP" and TCP in pkt:
                flags = pkt[TCP].flags
                # Count common flags
                if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                    tcp_flag_counts["SYN"] += 1
                if (flags & 0x12) == 0x12:               # SYN+ACK
                    tcp_flag_counts["SYN-ACK"] += 1
                if (flags & 0x10) and not (flags & 0x02): # ACK without SYN
                    tcp_flag_counts["ACK"] += 1
                if flags & 0x01:
                    tcp_flag_counts["FIN"] += 1
                if flags & 0x04:
                    tcp_flag_counts["RST"] += 1

                # Handshake detection (coarse but effective)
                if src and dst and sport is not None and dport is not None:
                    key = undirected_flow_key(proto, src, sport, dst, dport)
                    # Heuristics:
                    if flags & 0x02 and not (flags & 0x10):
                        handshake_state[key]["SYN"] = True
                    if (flags & 0x12) == 0x12:
                        # Seen SYN/ACK, likely reverse direction—still mark
                        handshake_state[key]["SYNACK"] = True
                    # ACK after SYN/ACK completes handshake
                    if (flags & 0x10) and handshake_state[key]["SYN"] and handshake_state[key]["SYNACK"]:
                        if not handshake_state[key]["ACK"]:
                            completed_handshakes += 1
                        handshake_state[key]["ACK"] = True

            # DNS stats + RTTs
            if DNS in pkt:
                d = pkt[DNS]
                if d.qr == 0:  # query
                    dns_query_count += 1
                    if d.qd is not None:
                        qname = d.qd.qname.decode(errors="ignore") if isinstance(d.qd.qname, bytes) else str(d.qd.qname)
                        dns_domains[qname.rstrip(".")] += 1
                    if src and dst:
                        pending_queries[(d.id, src, dst)] = ts
                else:          # response
                    dns_resp_count += 1
                    # NXDOMAIN rcode == 3
                    if d.rcode == 3:
                        dns_nxdomain_count += 1
                    if src and dst:
                        # Match reverse tuple to find original query
                        key = (d.id, dst, src)
                        t0 = pending_queries.pop(key, None)
                        if t0 is not None:
                            rtt_ms = (ts - t0) * 1000.0
                            dns_rtts_ms.append(rtt_ms)

    # Prepare report
    total_packets = sum(proto_counts.values())
    unique_flows = len(flow_set)
    top_domains = dns_domains.most_common(5)
    avg_dns_rtt = (sum(dns_rtts_ms) / len(dns_rtts_ms)) if dns_rtts_ms else None

    with open(report_path, "w", encoding="utf-8") as r:
        r.write("PCAP Packet Summary Report\n")
        r.write("==========================\n\n")
        r.write(f"Input PCAP: {os.path.abspath(args.pcap)}\n")
        r.write(f"Total packets processed: {total_packets}\n")
        r.write(f"Unique flows (TCP/UDP, direction-agnostic): {unique_flows}\n\n")

        r.write("Protocol counts:\n")
        for p, c in proto_counts.most_common():
            r.write(f"  - {p}: {c}\n")
        r.write("\n")

        r.write("TCP flag counts:\n")
        for flag in ["SYN", "SYN-ACK", "ACK", "FIN", "RST"]:
            r.write(f"  - {flag}: {tcp_flag_counts.get(flag, 0)}\n")
        r.write(f"\nDetected completed TCP handshakes: {completed_handshakes}\n\n")

        r.write("DNS statistics:\n")
        r.write(f"  - Queries:   {dns_query_count}\n")
        r.write(f"  - Responses: {dns_resp_count}\n")
        r.write(f"  - NXDOMAIN:  {dns_nxdomain_count}\n")
        r.write(f"  - Unique queried domains: {len(dns_domains)}\n")
        if top_domains:
            r.write("  - Top 5 queried domains:\n")
            for dom, cnt in top_domains:
                r.write(f"      * {dom} — {cnt}\n")
        if avg_dns_rtt is not None:
            r.write(f"  - Avg DNS RTT: {avg_dns_rtt:.2f} ms (based on {len(dns_rtts_ms)} matches)\n")
        else:
            r.write("  - Avg DNS RTT: N/A (no matched query/response pairs)\n")

    print(f"[OK] Wrote {csv_path}")
    print(f"[OK] Wrote {report_path}")


if __name__ == "__main__":
    main()
