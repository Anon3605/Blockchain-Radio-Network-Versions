#!/usr/bin/env python3
"""
Simplified Radio A - Fully Automated for Testing
Sends messages via UDP to producer node
"""

import socket
import time
import sys
import signal
import threading

class RadioA:
    def __init__(self):
        # UDP socket for sending to producer
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.producer_host = 'producer-node'
        self.producer_port = 12345
        
        # UDP socket for receiving from RadioB (optional)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.bind(('0.0.0.0', 54321))
        self.recv_socket.settimeout(0.5)
        
        print("="*60)
        print("RADIO A - Initialized (Automated Mode)")
        print("="*60)
        print(f"Sending to: {self.producer_host}:{self.producer_port}")
        print(f"Receiving on: 0.0.0.0:54321")
        print("="*60)
        print()
        
        self.running = True
        self.received_count = 0
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print(f"\n\nShutting down Radio A...")
        print(f"Total replies received: {self.received_count}")
        self.running = False
        sys.exit(0)
    
    def send_message(self, message):
        """Send message to producer"""
        try:
            self.send_socket.sendto(
                message.encode('utf-8'),
                (self.producer_host, self.producer_port)
            )
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] SENT: {message}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send: {e}")
            return False
    
    def receive_listener(self):
        """Background thread: Listen for replies from RadioB"""
        print(" Reply listener started...\n")
        while self.running:
            try:
                data, addr = self.recv_socket.recvfrom(4096)
                message = data.decode('utf-8')
                self.received_count += 1
                timestamp = time.strftime("%H:%M:%S")
                print(f"\n [{timestamp}] REPLY from RadioB: {message}")
                print()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    time.sleep(0.1)
    
    def run_auto(self, count=10, interval=5):
        """
        Fully automated mode - sends messages continuously
        No waiting for replies!
        """
        print(f" Automated mode: Sending {count} messages")
        print(f" Interval: {interval} seconds between messages")
        print(f" Messages will send regardless of replies\n")
        
        # Start background listener for replies
        listener_thread = threading.Thread(target=self.receive_listener, daemon=True)
        listener_thread.start()
        
        # Send messages on schedule
        for i in range(1, count + 1):
            if not self.running:
                break
            
            message = f"Test message {i} from RadioA"
            self.send_message(message)
            
            # Wait for next send interval
            if i < count:  # Don't wait after last message
                time.sleep(interval)
        
        print(f"\n Finished sending {count} messages")
        print(f" Received {self.received_count} replies")
        print(" Still listening for late replies... (Press Ctrl+C to exit)")
        
        # Keep listening for replies
        while self.running:
            time.sleep(1)


def main():
    radio = RadioA()
    
    # Parse command line arguments
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5
    
    radio.run_auto(count, interval)


if __name__ == '__main__':
    main()