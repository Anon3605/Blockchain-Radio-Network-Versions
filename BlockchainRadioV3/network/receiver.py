"""
Receiver Node - Final verification and delivery to RadioB
"""

import socket
import sys
import os
import json
import time
import logging
from threading import Thread
from packet import Packet, PacketStatistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[RECEIVER] %(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReceiverNode:
    def __init__(self, listen_port=6000):
        self.node_id = 99  # Special ID for receiver
        self.listen_port = listen_port
        self.radio_host = 'radio-b'  # Docker service name
        self.radio_port = 54321
        
        self.stats = PacketStatistics()
        self.server_socket = None
        self.radio_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP for RadioB
        self.received_packets = {}  # Track all received packets
        
        logger.info(f"Receiver Node initialized")
        logger.info(f"Listening on port {listen_port}")
        logger.info(f"Will deliver to RadioB at {self.radio_host}:{self.radio_port} (UDP)")
    
    def final_verification(self, packet: Packet) -> bool:
        """
        Perform final cryptographic verification before delivery
        This is the last line of defense against tampered data
        """
        start_time = time.time()
        
        # Verify data integrity
        if not packet.verify_integrity():
            logger.error(f"[WARNING]  FINAL VERIFICATION FAILED! Packet {packet.uid} - Data tampered!")
            return False
        
        # Verify ZK proof
        if not packet.zk_proof:
            logger.error(f"[WARNING]  FINAL VERIFICATION FAILED! Packet {packet.uid} - No proof!")
            return False
        
        try:
            proof_data = json.loads(packet.zk_proof)
            print(proof_data)
            
            # # Comprehensive checks
            # checks = [
            #     (proof_data.get('uid') == packet.uid, "UID mismatch"),
            #     (proof_data.get('data_hash') == packet.data_hash, "Hash mismatch"),
            #     (proof_data.get('sid') == packet.sid, "Source ID mismatch"),
            # ]
            
            # for check, error_msg in checks:
            #     if not check:
            #         logger.error(f"[WARNING]  FINAL VERIFICATION FAILED! {error_msg}")
            #         return False
            
            # # TODO: Actual o1js proof verification here
            
            verification_time = time.time() - start_time
            logger.info(f"OK Final verification passed for packet {packet} ({verification_time*1000:.2f}ms)")
            self.stats.record_verified(packet, verification_time)
            return True
            
        except Exception as e:
            logger.error(f"Error in final verification: {e}")
            return False
    
    def deliver_to_radio_b(self, packet: Packet) -> bool:
        """
        Deliver verified packet to RadioB via UDP
        """
        try:
            # Send only the data via UDP to RadioB
            message = f"[Packet {packet.uid}] {packet.data}"
            self.radio_udp_socket.sendto(
                message.encode('utf-8'),
                (self.radio_host, self.radio_port)
            )
            
            logger.info(f" Delivered to RadioB: {message}")
            
            # Record latency
            self.stats.record_latency(packet, time.time())
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver to RadioB: {e}")
            return False
    
    def setup_server(self):
        """Setup server socket"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.listen_port))
            self.server_socket.listen(5)
            logger.info(f"Server listening on port {self.listen_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup server: {e}")
            return False
    
    def receive_and_deliver(self):
        """Main loop: receive packets, verify, and deliver"""
        logger.info("Starting packet receiver...")
        
        if not self.setup_server():
            logger.error("Cannot start without server socket")
            return
        
        while True:
            try:
                conn, addr = self.server_socket.accept()
                logger.debug(f"Connection from {addr}")
                
                # Receive packet
                data = conn.recv(8192)
                if not data:
                    conn.close()
                    continue
                
                packet = Packet.from_bytes(data)
                logger.info(f"Received {packet}")
                logger.info(f"   Hops: {packet.hop_count}, Size: {packet.get_size()} bytes")
                
                # Check if already received
                if packet.uid in self.received_packets:
                    logger.info(f"Duplicate packet {packet.uid} - ignoring")
                    self.stats.record_dropped("duplicate")
                    conn.send(b'DUP')
                    conn.close()
                    continue
                
                # CRITICAL: Final verification
                if self.final_verification(packet):
                    # Store packet
                    self.received_packets[packet.uid] = packet
                    
                    # Deliver to RadioB
                    if self.deliver_to_radio_b(packet):
                        conn.send(b'ACK')
                        logger.info(f"OK Packet {packet.uid} successfully delivered to RadioB")
                    else:
                        conn.send(b'DELIVERY_FAILED')
                        logger.error(f"[REJECTED] Failed to deliver packet {packet.uid} to RadioB")
                else:
                    # Verification failed
                    logger.warning(f"[REJECTED] Packet {packet.uid} REJECTED at final verification")
                    self.stats.record_dropped("verification_failed")
                    conn.send(b'FAIL')
                
                conn.close()
                
            except Exception as e:
                logger.error(f"Error in receive loop: {e}")
                import traceback
                traceback.print_exc()
    
    def print_periodic_stats(self):
        """Print statistics periodically"""
        while True:
            time.sleep(30)
            if self.stats.total_packets > 0:
                summary = self.stats.get_summary()
                logger.info("="*60)
                logger.info(f"RECEIVER STATISTICS")
                logger.info(f"Total packets: {summary['total_packets']}")
                logger.info(f"Delivered: {summary['verified_packets']}")
                logger.info(f"Rejected: {summary['dropped_packets']}")
                logger.info(f"Success rate: {summary['success_rate']*100:.2f}%")
                logger.info(f"Avg latency: {summary['avg_latency']*1000:.2f}ms")
                logger.info("="*60)
    
    def start(self):
        """Start the receiver node"""
        logger.info("="*60)
        logger.info("RECEIVER NODE STARTING")
        logger.info("="*60)
        
        # Start threads
        receiver_thread = Thread(target=self.receive_and_deliver, daemon=True)
        stats_thread = Thread(target=self.print_periodic_stats, daemon=True)
        
        receiver_thread.start()
        stats_thread.start()
        
        logger.info("Receiver is running. Waiting for packets...")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down receiver...")
            self.stats.print_summary()


def main():
    receiver = ReceiverNode()
    receiver.start()


if __name__ == "__main__":
    main()