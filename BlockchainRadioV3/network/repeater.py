"""
Repeater Node - Verifies ZK proofs and forwards packets
Acts as a mesh network node that can detect and drop tampered packets
"""

import socket
import sys
import os
import json
import time
import logging
import subprocess
import argparse
from threading import Thread
from packet import Packet, PacketQueue, PacketStatistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[REPEATER-%(name)s] %(asctime)s - %(levelname)s - %(message)s'
)


class RepeaterNode:
    def __init__(self, node_id, listen_port):
        self.node_id = node_id
        self.listen_port = listen_port
        self.next_hop = os.getenv('NEXT_HOP', None)
        
        # Parse next hop if exists
        if self.next_hop:
            self.next_host, self.next_port = self.next_hop.split(':')
            self.next_port = int(self.next_port)
        else:
            self.next_host = None
            self.next_port = None
        
        self.packet_queue = PacketQueue()
        self.stats = PacketStatistics()
        self.logger = logging.getLogger(str(node_id))
        
        # Socket for incoming connections
        self.server_socket = None
        
        self.logger.info(f"Repeater Node {node_id} initialized")
        self.logger.info(f"Listening on port {listen_port}")
        if self.next_hop:
            self.logger.info(f"Next hop: {self.next_hop}")
        else:
            self.logger.info("Last repeater before receiver")
    
    def verify_zk_proof(self, packet: Packet) -> bool:
        """
        Verify the zero-knowledge proof using o1js
        
        Returns True if proof is valid, False if tampered or invalid.
        """
        start_time = time.time()
        
        # Step 1: Verify data integrity (hash check)
        if not packet.verify_integrity():
            self.logger.warning(f"[WARNING]  TAMPERED PACKET DETECTED! UID={packet.uid} - Hash mismatch")
            return False
        
        # Step 2: Verify ZK proof exists
        if not packet.zk_proof:
            self.logger.warning(f"[WARNING]  INVALID PACKET! UID={packet.uid} - No ZK proof")
            return False
        
        # Step 3: Verify the actual ZK proof with o1js
        try:
            proof_data = json.loads(packet.zk_proof)
            
            # Check if it's a real proof or simulated
            if proof_data.get('proof_type') == 'simulated':
                # Fallback verification for simulated proofs
                return self.verify_simulated_proof(packet, proof_data)
            
            # Call Node.js script to verify real proof
            self.logger.debug(f"Verifying ZK proof for packet {packet.uid}...")
            
            result = subprocess.run(
                ['sh', '-c', f'cd /app/zkapp && node build/verify_proof.js \'{json.dumps(proof_data)}\''],
                capture_output=True,
                text=True,
                timeout=30  # 30 second timeout
            )
            
            if result.returncode != 0:
                self.logger.warning(f"[WARNING]  INVALID PROOF! UID={packet.uid}")
                self.logger.debug(f"Verification error: {result.stderr}")
                return False
            
            # Parse verification result
            verify_output = json.loads(result.stdout)
            verification_time = time.time() - start_time
            
            if verify_output.get('valid'):
                self.logger.info(f"OK Packet {packet.uid} verified in {verification_time*1000:.2f}ms")
                self.stats.record_verified(packet, verification_time)
                return True
            else:
                self.logger.warning(f"[REJECTED] Packet {packet.uid} verification FAILED: {verify_output.get('reason')}")
                self.stats.record_dropped("invalid_proof")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Proof verification timeout for packet {packet.uid}")
            return False
        except Exception as e:
            self.logger.error(f"Error verifying proof: {e}")
            return False
    
    def verify_simulated_proof(self, packet: Packet, proof_data: dict) -> bool:
        """Fallback verification for simulated proofs"""
        verification_time = time.time() - time.time()
        
        # Verify proof matches packet data
        if proof_data.get('uid') != packet.uid:
            return False
        if proof_data.get('data_hash') != packet.data_hash:
            return False
        
        self.logger.info(f"OK Packet {packet.uid} verified (simulated) in {verification_time*1000:.2f}ms")
        self.stats.record_verified(packet, verification_time)
        return True
    
    def setup_server(self):
        """Setup server socket for incoming packets"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.listen_port))
            self.server_socket.listen(5)
            self.logger.info(f"Server listening on port {self.listen_port}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to setup server: {e}")
            return False
    
    def receive_packets(self):
        """Thread: Receive and process incoming packets"""
        self.logger.info("Starting packet receiver thread...")
        
        if not self.setup_server():
            self.logger.error("Cannot start without server socket")
            return
        
        while True:
            try:
                conn, addr = self.server_socket.accept()
                self.logger.debug(f"Connection from {addr}")
                
                # Receive packet data
                data = conn.recv(8192)  # Increased buffer for proofs
                if not data:
                    conn.close()
                    continue
                
                # Deserialize packet
                packet = Packet.from_bytes(data)
                self.logger.info(f"Received {packet}")
                
                # Check for duplicates
                if not self.packet_queue.add(packet):
                    self.logger.info(f"Duplicate packet {packet.uid} - dropping")
                    self.stats.record_dropped("duplicate")
                    conn.send(b'DUP')
                    conn.close()
                    continue
                
                # CRITICAL: Verify ZK proof
                if self.verify_zk_proof(packet):
                    # Update repeater ID
                    packet.update_repeater(self.node_id)
                    
                    # Send acknowledgment
                    conn.send(b'ACK')
                    self.logger.info(f"OK Packet {packet.uid} accepted and queued for forwarding")
                else:
                    # Proof verification failed - DROP THE PACKET
                    self.logger.warning(f"[REJECTED] Packet {packet.uid} DROPPED due to invalid proof")
                    conn.send(b'FAIL')
                
                conn.close()
                
            except Exception as e:
                self.logger.error(f"Error receiving packet: {e}")
                import traceback
                traceback.print_exc()
    
    def forward_packets(self):
        """Thread: Forward verified packets to next hop"""
        if not self.next_hop:
            self.logger.info("No next hop configured - acting as last repeater")
            return
        
        self.logger.info(f"Starting packet forwarder thread to {self.next_hop}...")
        
        while True:
            packet = self.packet_queue.get(timeout=1.0)
            if packet is None:
                continue
            
            try:
                # Connect to next hop
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.next_host, self.next_port))
                
                # Forward packet
                sock.sendall(packet.to_bytes())
                self.logger.info(f"→ Forwarded {packet} to {self.next_host}:{self.next_port}")
                
                # Wait for acknowledgment
                ack = sock.recv(1024)
                if ack == b'ACK':
                    self.logger.debug(f"Packet {packet.uid} acknowledged by next hop")
                elif ack == b'FAIL':
                    self.logger.warning(f"Packet {packet.uid} rejected by next hop")
                
                sock.close()
                
            except Exception as e:
                self.logger.error(f"Error forwarding packet: {e}")
                time.sleep(1)
    
    def start(self):
        """Start the repeater node"""
        self.logger.info("="*60)
        self.logger.info(f"REPEATER NODE {self.node_id} STARTING")
        self.logger.info("="*60)
        
        # Start threads
        receiver_thread = Thread(target=self.receive_packets, daemon=True)
        forwarder_thread = Thread(target=self.forward_packets, daemon=True)
        
        receiver_thread.start()
        forwarder_thread.start()
        
        self.logger.info(f"Repeater {self.node_id} is running and ready to verify packets.")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(10)
                # Print periodic stats
                if self.stats.total_packets > 0:
                    success_rate = (self.stats.verified_packets / self.stats.total_packets) * 100
                    self.logger.info(
                        f"Stats: {self.stats.verified_packets} verified, "
                        f"{self.stats.dropped_packets} dropped "
                        f"(Success: {success_rate:.1f}%)"
                    )
        except KeyboardInterrupt:
            self.logger.info(f"Shutting down repeater {self.node_id}...")
            self.stats.print_summary()


def main():
    parser = argparse.ArgumentParser(description='Radio Mesh Repeater Node')
    parser.add_argument('--id', type=int, required=True, help='Node ID')
    parser.add_argument('--port', type=int, required=True, help='Listen port')
    args = parser.parse_args()
    
    repeater = RepeaterNode(args.id, args.port)
    repeater.start()


if __name__ == "__main__":
    main()