#!/usr/bin/env python3
"""
Generate real SMTP email traffic across IPsec tunnel
Usage: python3 gen_email.py [target_ip] [duration_seconds] [port]
"""
import sys
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

def send_one_email(target_ip, port, count):
    msg = MIMEMultipart()
    msg['From'] = f"analyst-nodeA@secops.local"
    msg['To'] = f"soc-receiver@nodeB.local"
    msg['Subject'] = f"Security Incident Advisory #{count:04d} - IPsec Tunnel Verification"

    body = f"""Hello SOC Team,

This is automated test email message #{count} transmitted over the encrypted IPsec SA tunnel.
Security parameters verification: AES-256 / SHA-256 / DH Group negotiation.
Timestamp: {time.ctime()}

Please confirm reception.

Regards,
IPsec Network Automation Engine
"""
    msg.attach(MIMEText(body, 'plain'))

    # Attach sample log file
    attachment = MIMEApplication(b"LOG_ENTRY: 2026-08-30 SA_ESTABLISHED [node-a -> node-b] SPI=0x7f8841a0\n" * 15)
    attachment.add_header('Content-Disposition', 'attachment', filename=f'sa_log_{count}.txt')
    msg.attach(attachment)

    with smtplib.SMTP(target_ip, port, timeout=5) as server:
        server.send_message(msg)

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "172.28.0.20"
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 2525

    print(f"[Traffic Gen: Email] Sending real SMTP emails to {target_ip}:{port} for {duration}s...")
    start = time.time()
    count = 0
    while time.time() - start < duration:
        try:
            count += 1
            send_one_email(target_ip, port, count)
            # Send an email every 1.5 - 2.5 seconds
            time.sleep(1.8)
        except Exception as e:
            time.sleep(1.0)
    print(f"[Traffic Gen: Email] Sent {count} emails successfully.")

if __name__ == "__main__":
    main()
