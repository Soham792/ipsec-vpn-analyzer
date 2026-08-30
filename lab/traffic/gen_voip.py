#!/usr/bin/env python3
"""
Generate VoIP / RTP-like UDP traffic across IPsec tunnel
Packet size: ~160-200 bytes payload (mimicking G.711 codec frames)
Interval: Strictly ~20ms (+/- 1ms jitter)
Usage: python3 gen_voip.py [target_ip] [duration_seconds] [port]
"""
import sys
import time
import socket
import struct
import random

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "172.28.0.20"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5004

    print(f"[Traffic Gen: VoIP] Sending RTP voice packets (160-200B @ 20ms) to {target_ip}:{port} for {duration}s...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    timestamp = random.randint(10000, 50000)
    ssrc = random.randint(100000, 999999)

    start_time = time.time()
    next_send_time = start_time

    while time.time() - start_time < duration:
        # Construct realistic 12-byte RTP header
        # V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU/G.711)
        rtp_hdr = struct.pack("!BBHII", 0x80, 0x00, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
        
        # 160 bytes G.711 audio payload + slight variation
        payload_size = 160 + random.randint(0, 16)
        audio_payload = os.urandom(payload_size) if hasattr(os, 'urandom') else bytes([random.randint(0, 255) for _ in range(payload_size)])
        
        packet = rtp_hdr + audio_payload
        try:
            sock.sendto(packet, (target_ip, port))
        except Exception:
            pass

        seq += 1
        timestamp += 160 # 20ms of 8000Hz audio
        
        next_send_time += 0.020
        sleep_time = next_send_time - time.time()
        if sleep_time > 0:
            time.sleep(sleep_time)

    sock.close()
    print(f"[Traffic Gen: VoIP] Finished sending {seq} VoIP packets.")

if __name__ == "__main__":
    import os
    main()
