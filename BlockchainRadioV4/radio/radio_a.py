#!/usr/bin/env python3
"""
Radio A - Message Sender for Blockchain Radio V4

Sends voice/data messages to the mesh network via Producer node.
In real deployment, this would be connected to actual radio hardware.
"""

import socket
import time
import sys
import signal
import threading
import os


class RadioA:
    def __init__(
        self,
        producer_host: str = 'producer-node',
        producer_port: int = 12345
    ):
        self.producer_host = os.getenv('PRODUCER_HOST', producer_host)
        self.producer_port = int(os.getenv('PRODUCER_PORT', producer_port))
        
        # UDP socket for sending to producer
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # UDP socket for receiving replies (optional)
        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.bind(('0.0.0.0', 54321))
        self.recv_socket.settimeout(0.5)
        
        print("=" * 60)
        print("RADIO A - Blockchain Radio V4")
        print("=" * 60)
        print(f"Sending to: {self.producer_host}:{self.producer_port}")
        print(f"Receiving on: 0.0.0.0:54321")
        print("=" * 60)
        print()
        
        self.running = True
        self.sent_count = 0
        self.received_count = 0
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, sig, frame):
        print(f"\n\nShutting down Radio A...")
        print(f"Messages sent: {self.sent_count}")
        print(f"Replies received: {self.received_count}")
        self.running = False
        sys.exit(0)
    
    def send_message(self, message: str) -> bool:
        """Send message to producer"""
        try:
            self.send_socket.sendto(
                message.encode('utf-8'),
                (self.producer_host, self.producer_port)
            )
            self.sent_count += 1
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] SENT #{self.sent_count}: {message}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send: {e}")
            return False
    
    def receive_listener(self):
        """Background thread: Listen for replies"""
        print("Reply listener started...\n")
        while self.running:
            try:
                data, addr = self.recv_socket.recvfrom(4096)
                message = data.decode('utf-8')
                self.received_count += 1
                timestamp = time.strftime("%H:%M:%S")
                print(f"\n[{timestamp}] REPLY from RadioB: {message}")
                print()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    time.sleep(0.1)
    
    def run_auto(self, count: int = 10, interval: float = 5.0):
        """
        Automated mode - sends messages continuously
        
        This simulates real voice/data transmission after
        session establishment.
        """
        print(f"Automated mode: Sending {count} messages")
        print(f"Interval: {interval} seconds")
        print(f"First message triggers session establishment (~120s in production)")
        print(f"Subsequent messages use fast HMAC authentication (~0.1ms)")
        print()
        
        # Start reply listener
        listener_thread = threading.Thread(target=self.receive_listener, daemon=True)
        listener_thread.start()
        
        # Wait a moment for network to be ready
        print("Waiting for network to be ready...")
        time.sleep(5)
        
        # Send messages
        for i in range(1, count + 1):
            if not self.running:
                break
            
            message = f"Voice data packet {i} from RadioA - Blockchain Radio V4"
            self.send_message(message)
            
            if i < count:
                time.sleep(interval)
        
        print(f"\nFinished sending {count} messages")
        print(f"Received {self.received_count} replies")
        print("Still listening for late replies... (Ctrl+C to exit)")
        
        # Keep listening
        while self.running:
            time.sleep(1)
    
    def run_interactive(self):
        """Interactive mode - manual message entry"""
        print("Interactive mode: Type messages and press Enter")
        print("Type 'quit' to exit")
        print()
        
        # Start reply listener
        listener_thread = threading.Thread(target=self.receive_listener, daemon=True)
        listener_thread.start()
        
        while self.running:
            try:
                message = input("Message: ").strip()
                if message.lower() == 'quit':
                    break
                if message:
                    self.send_message(message)
            except EOFError:
                break
        
        self.running = False


def main():
    radio = RadioA()
    
    # Parse command line arguments
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    interval = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        radio.run_interactive()
    else:
        radio.run_auto(count, interval)


if __name__ == '__main__':
    main()
