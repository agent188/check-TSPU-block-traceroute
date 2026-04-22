#!/usr/bin/env python3
"""
TCP Traceroute.

Example usage:
    sudo python3 tcp_tspu_traceroute.py --target 185.9.145.10 --dport 443 \
        --low-ttl-syn 5 --low-ttl-ack 5 --normal-ttl 27 \
        --payload-hex "1603010200010001fc0303cf6bb4ab83c7a52eeeb467a980f64b2ed1fc8dc05adb8a78943191bfda2c3a26205c82fb2f0541a936ebcc80f6ea67cf93971b90f2fd16e894d7e503adcc0536bf003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000012001000000d7275747261636b65722e6f7267000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d002079a20294babf66e56e3cab2ec676e23b5c3d2a3aea19eb56bda8d1e13c352263001500b4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
"""

from scapy.all import *
import time
import random
import subprocess
import sys
import os
import argparse

class MyTCPSession:
    def __init__(self, target, dport, sport=None,
                 low_ttl_syn=5, low_ttl_ack=5, normal_ttl=27):
        self.target = target
        self.dport = dport
        self.sport = sport if sport is not None else random.randint(1024, 65535)
        self.seq = 1000
        self.low_ttl_syn = low_ttl_syn
        self.low_ttl_ack = low_ttl_ack
        self.normal_ttl = normal_ttl
        self.syn_ack = None

    def __enter__(self):
        # 1. Send dummy SYN with low TTL
        print(f"[*] Sending dummy SYN with TTL={self.low_ttl_syn}...")
        syn_low = IP(dst=self.target, ttl=self.low_ttl_syn) / TCP(
            sport=self.sport, dport=self.dport, flags="S", seq=self.seq
        )
        send(syn_low, verbose=0)

        # 2. Send working SYN with normal TTL
        print(f"[*] Sending working SYN with TTL={self.normal_ttl}...")
        syn_norm = IP(dst=self.target, ttl=self.normal_ttl) / TCP(
            sport=self.sport, dport=self.dport, flags="S", seq=self.seq
        )
        self.syn_ack = sr1(syn_norm, timeout=3, verbose=0)

        if not self.syn_ack or not self.syn_ack.haslayer(TCP):
            raise Exception("Failed to receive SYN-ACK")

        print(f"[+] Received SYN-ACK from {self.syn_ack.src}")

        # 3. Send dummy ACK with low TTL
        print(f"[*] Sending dummy ACK with TTL={self.low_ttl_ack}...")
        ack_low = IP(dst=self.target, ttl=self.low_ttl_ack) / TCP(
            sport=self.sport, dport=self.dport, flags="A",
            seq=self.syn_ack.ack, ack=self.syn_ack.seq + 1
        )
        send(ack_low, verbose=0)

        # 4. Send working ACK with normal TTL
        print(f"[*] Sending working ACK with TTL={self.normal_ttl}...")
        ack_norm = IP(dst=self.target, ttl=self.normal_ttl) / TCP(
            sport=self.sport, dport=self.dport, flags="A",
            seq=self.syn_ack.ack, ack=self.syn_ack.seq + 1
        )
        send(ack_norm, verbose=0)
        print(f"[+] Connection established (source port {self.sport})")
        return self

    def __exit__(self, *args):
        print("[*] Closing connection (FIN)...")
        fin = IP(dst=self.target) / TCP(
            sport=self.sport, dport=self.dport, flags="FA",
            seq=self.syn_ack.ack, ack=self.syn_ack.seq + 1
        )
        send(fin, verbose=0)

    def get_ack_info(self):
        return self.syn_ack.ack, self.syn_ack.seq + 1


def block_rst(sport):
    """
    Block outgoing RST packets from the specified source port.
    The rule is inserted at the top of the OUTPUT chain.
    """
    cmd = [
        "iptables", "-I", "OUTPUT", "1",
        "-p", "tcp", "--tcp-flags", "RST", "RST",
        "--sport", str(sport),
        "-j", "DROP"
    ]
    subprocess.run(cmd, check=True)
    print(f"[*] RST packets from port {sport} are blocked (rule at the top of the chain).")

def unblock_rst(sport):
    """Remove the RST blocking rule for the specified port."""
    cmd = [
        "iptables", "-D", "OUTPUT",
        "-p", "tcp", "--tcp-flags", "RST", "RST",
        "--sport", str(sport),
        "-j", "DROP"
    ]
    subprocess.run(cmd, check=True)
    print(f"[*] RST blocking for port {sport} removed.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP Traceroute"
    )
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--dport", type=int, required=True, help="Destination port")
    parser.add_argument("--sport", type=int, help="Source port (random by default)")
    parser.add_argument("--low-ttl-syn", type=int, default=5, help="TTL for dummy SYN (default: 5)")
    parser.add_argument("--low-ttl-ack", type=int, default=5, help="TTL for dummy ACK (default: 5)")
    parser.add_argument("--normal-ttl", type=int, default=27, help="Working TTL for SYN/ACK and probes (default: 27)")
    parser.add_argument("--payload-hex", required=True, help="Payload in hex format (e.g., '474554202f...')")
    parser.add_argument("--max-ttl", type=int, default=30, help="Maximum TTL for traceroute (default: 30)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout for probe response in seconds (default: 2.0)")
    return parser.parse_args()


def hex_to_bytes(hex_str):
    """Convert a hex string to bytes, ignoring spaces and non-hex characters."""
    hex_clean = ''.join(c for c in hex_str if c.isalnum())
    try:
        return bytes.fromhex(hex_clean)
    except ValueError as e:
        sys.exit(f"Error in hex string: {e}")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Root privileges required. Run with sudo.")
        sys.exit(1)

    args = parse_args()

    # Convert hex payload to bytes
    payload_bytes = hex_to_bytes(args.payload_hex)

    # Display parameters
    print(f"[*] Target: {args.target}:{args.dport}")
    print(f"[*] Source port: {'random' if args.sport is None else args.sport}")
    print(f"[*] TTL: SYN_low={args.low_ttl_syn}, ACK_low={args.low_ttl_ack}, normal={args.normal_ttl}")
    print(f"[*] Payload (hex): {args.payload_hex[:50]}...")

    # Determine the source port (may be provided or generated inside the session).
    # To ensure iptables blocking works correctly, we need to know the port in advance.
    sport = args.sport if args.sport else random.randint(1024, 65535)

    block_rst(sport)
    try:
        with MyTCPSession(
            target=args.target,
            dport=args.dport,
            sport=sport,
            low_ttl_syn=args.low_ttl_syn,
            low_ttl_ack=args.low_ttl_ack,
            normal_ttl=args.normal_ttl
        ) as sess:
            seq_val, ack_val = sess.get_ack_info()
            print("[*] Starting traceroute with PSH+ACK probes...")
            for ttl in range(1, args.max_ttl + 1):
                probe = IP(dst=args.target, ttl=ttl) / TCP(
                    sport=sess.sport, dport=args.dport, flags="PA",
                    seq=seq_val, ack=ack_val
                ) / Raw(load=payload_bytes)

                ans = sr1(probe, timeout=args.timeout, verbose=0)

                if ans is None:
                    print(f"{ttl:2d}: * * *")
                elif ans.haslayer(ICMP) and ans.getlayer(ICMP).type == 11:
                    print(f"{ttl:2d}: {ans.src} (ICMP TTL Exceeded)")
                elif ans.haslayer(TCP):
                    print(f"{ttl:2d}: {ans.src} (Target reached!)")
                    break
                else:
                    print(f"{ttl:2d}: unexpected response {ans.summary()}")

                time.sleep(0.1)
    finally:
        unblock_rst(sport)
