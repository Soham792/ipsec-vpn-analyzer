#!/usr/bin/env python3
"""
Generate Instant Messaging / Chat UDP traffic across IPsec tunnel
Packet size: ~60-150 bytes (small message bursts)
Interval: Bursty, irregular (user typing bursts, followed by silence pauses)
Usage: python3 gen_chat.py [target_ip] [duration_seconds] [port]
"""
import sys
import os
import time
import socket
import struct
import random
import json

SAMPLE_MESSAGES = [
    {"type": "chat", "sender": "alice", "msg": "Hey, did you check the IPsec security report?"},
    {"type": "chat", "sender": "bob", "msg": "Yes, reviewing the DH group and AES-GCM config now."},
    {"type": "presence", "sender": "alice", "status": "online"},
    {"type": "typing", "sender": "bob", "active": True},
    {"type": "chat", "sender": "bob", "msg": "Looks solid. All tests passing."},
    {"type": "ack", "msg_id": 1042},
    {"type": "chat", "sender": "alice", "msg": "Great, generating final PDF report."},
    {"type": "presence", "sender": "alice", "status": "away"}
]

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "172.28.0.20"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5222

    print(f"[Traffic Gen: Chat] Sending chat burst packets (60-150B) to {target_ip}:{port} for {duration}s...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start_time = time.time()
    count = 0

    while time.time() - start_time < duration:
        # A burst consists of 2 to 5 rapid messages (typing back and forth)
        burst_size = random.randint(2, 5)
        for _ in range(burst_size):
            if time.time() - start_time >= duration:
                break
            msg_obj = random.choice(SAMPLE_MESSAGES)
            msg_obj["ts"] = time.time()
            data = json.dumps(msg_obj).encode("utf-8")
            
            # Ensure packet is between 60 and 150 bytes
            if len(data) < 60:
                data += b" " * (60 - len(data))
            elif len(data) > 150:
                data = data[:150]

            try:
                sock.sendto(data, (target_ip, port))
                count += 1
            except Exception:
                pass

            # Intra-burst delay (fast typing: 100ms - 400ms)
            time.sleep(random.uniform(0.1, 0.4))

        # Inter-burst delay (thinking / idle: 1.5s - 3.5s)
        time.sleep(random.uniform(1.5, 3.5))

    sock.close()
    print(f"[Traffic Gen: Chat] Finished sending {count} chat packets.")

if __name__ == "__main__":
    main()
