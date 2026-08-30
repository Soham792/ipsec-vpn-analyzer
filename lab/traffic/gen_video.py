#!/usr/bin/env python3
"""
Generate Video Streaming UDP traffic across IPsec tunnel
Packet size: ~1200-1400 bytes payload (mimicking H.264/H.265 video slices)
Interval: ~8-10ms with periodic I-frame burst clusters
Usage: python3 gen_video.py [target_ip] [duration_seconds] [port]
"""
import sys
import os
import time
import socket
import struct
import random

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "172.28.0.20"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5006

    print(f"[Traffic Gen: Video] Sending video stream packets (1200-1400B @ 8-10ms) to {target_ip}:{port} for {duration}s...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    timestamp = random.randint(10000, 50000)
    ssrc = random.randint(100000, 999999)

    start_time = time.time()
    next_send_time = start_time
    frame_counter = 0

    while time.time() - start_time < duration:
        frame_counter += 1
        # Every 30 frames simulate an I-frame burst (3-4 MTU packets in quick succession)
        is_keyframe = (frame_counter % 30 == 0)
        packets_in_frame = random.randint(3, 5) if is_keyframe else 1

        for _ in range(packets_in_frame):
            # RTP header for H.264 payload type (PT=96)
            rtp_hdr = struct.pack("!BBHII", 0x80, 0x60, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
            payload_len = random.randint(1200, 1380)
            payload = os.urandom(payload_len)
            
            packet = rtp_hdr + payload
            try:
                sock.sendto(packet, (target_ip, port))
            except Exception:
                pass
            seq += 1

        timestamp += 3000 # 90kHz clock for 30fps
        next_send_time += 0.009 # ~9ms inter-packet interval average
        sleep_time = next_send_time - time.time()
        if sleep_time > 0:
            time.sleep(sleep_time)

    sock.close()
    print(f"[Traffic Gen: Video] Finished sending {seq} video packets.")

if __name__ == "__main__":
    main()
