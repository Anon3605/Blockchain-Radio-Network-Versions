#!/usr/bin/env python3
"""
Simplified Radio B - Fully Automated with Auto-Reply
Receives messages from receiver node via UDP and optionally sends replies
"""

import socket
import time
import sys
import signal
import random

class RadioB:
    def __init__(self, auto_reply=False):
        # UDP socket for receiving from receiver
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.bind(('0.0.0.0', 54321))
        
        # UDP socket for sending replies to RadioA (optional)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.radio_a_host = 'radio-a'
        self.radio_a_port = 54321
        
        self.auto_reply = auto_reply
        
        print("="*60)
        print("RADIO B - Initialized (Automated Mode)")
        print("="*60)
        print(f"Receiving on: 0.0.0.0:54321")
        if auto_reply:
            print(f"Auto-reply enabled → {self.radio_a_host}:{self.radio_a_port}")
        print("="*60)
        print()
        
        self.running = True
        self.message_count = 0
        self.reply_count = 0
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print(f"\n\n" + "="*60)
        print("Shutting down Radio B...")
        print(f"Total messages received: {self.message_count}")
        if self.auto_reply:
            print(f"Total replies sent: {self.reply_count}")
        print("="*60)
        self.running = False
        sys.exit(0)
    
    def send_reply(self, original_msg, packet_id):
        """Send automatic reply back to RadioA"""
        if not self.auto_reply:
            return
        
        try:
            reply_messages = [
                f"ACK: Received packet {packet_id}",
                f"Roger that! Packet {packet_id} confirmed",
                f"Message received loud and clear #{packet_id}",
                f"Copy that, packet {packet_id}",
            ]
            reply = random.choice(reply_messages)
            
            self.send_socket.sendto(
                reply.encode('utf-8'),
                (self.radio_a_host, self.radio_a_port)
            )
            self.reply_count += 1
            print(f"     Sent reply: {reply}")
        except Exception as e:
            print(f"     [WARNING]  Failed to send reply: {e}")
    
    def receive_and_display(self):
        """Main receive loop - fully automated"""
        print("Listening for messages from mesh network...")
        if self.auto_reply:
            print("Auto-reply mode enabled")
        print("(Press Ctrl+C to exit)\n")
        
        while self.running:
            try:
                # Receive message
                data, addr = self.recv_socket.recvfrom(4096)
                message = data.decode('utf-8').strip()
                
                self.message_count += 1
                timestamp = time.strftime("%H:%M:%S")
                
                # Extract packet ID if present
                packet_id = self.message_count
                if "[Packet" in message:
                    try:
                        packet_id = int(message.split("[Packet ")[1].split("]")[0])
                    except:
                        pass
                
                # Display with nice formatting
                print(f"│ Message #{self.message_count:<5}  {timestamp:<15} From: {str(addr):<12} │")
                
                
                # Wrap long messages
                max_width = 56
                if len(message) <= max_width:
                    print(f"│ {message:<{max_width}} │")
                else:
                    words = message.split()
                    line = ""
                    for word in words:
                        if len(line) + len(word) + 1 <= max_width:
                            line += word + " "
                        else:
                            print(f"│ {line:<{max_width}} │")
                            line = word + " "
                    if line:
                        print(f"│ {line:<{max_width}} │")
                
                print("└" + "─" * 58 + "┘")
                
                # Send automatic reply if enabled
                if self.auto_reply:
                    # Small delay to simulate thinking
                    time.sleep(0.5)
                    self.send_reply(message, packet_id)
                
                print()  # Blank line for readability
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[WARNING]  [ERROR] {e}")
                    time.sleep(0.1)


def main():
    # Check if auto-reply is requested
    auto_reply = False
    if len(sys.argv) > 1 and sys.argv[1] in ['--reply', '-r', 'reply']:
        auto_reply = True
    
    radio = RadioB(auto_reply=auto_reply)
    radio.receive_and_display()


if __name__ == '__main__':
    main()