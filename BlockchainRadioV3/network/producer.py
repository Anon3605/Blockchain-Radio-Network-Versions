"""
Producer Node - Receives data from RadioA and generates ZK proofs
"""

import socket
import sys
import os
import json
import time
import logging
import subprocess
from threading import Thread
from packet import Packet, PacketQueue, PacketStatistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[PRODUCER] %(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProducerNode:
    def __init__(self, node_id=0, radio_host='0.0.0.0', radio_port=12345):
        self.node_id = node_id
        self.radio_host = radio_host  # Listen on all interfaces
        self.radio_port = int(os.getenv('RADIO_PORT', radio_port))
        self.next_hop = os.getenv('NEXT_HOP', 'repeater1:5001')
        
        # Parse next hop
        self.next_host, self.next_port = self.next_hop.split(':')
        self.next_port = int(self.next_port)
        
        self.packet_queue = PacketQueue()
        self.stats = PacketStatistics()
        self.uid_counter = 1
        
        # Create socket for receiving from RadioA
        self.radio_socket = None
        
        logger.info(f"Producer Node initialized")
        logger.info(f"Listening for RadioA on {self.radio_host}:{self.radio_port}")
        logger.info(f"Next hop: {self.next_host}:{self.next_port}")
    
    def generate_zk_proof(self, packet: Packet) -> str:
        """
        Generate zero-knowledge proof for packet data integrity using o1js
        """
        start_time = time.time()
        
        # Prepare data for proof generation
        proof_input = {
            "uid": packet.uid,
            "sid": packet.sid,
            "data": packet.data,
            "timestamp": int(packet.timestamp * 1000)  # Convert to milliseconds
        }
        
        try:
            # Call Node.js script to generate proof
            logger.info(f"Generating ZK proof for packet {packet.uid}...")
            
            # IMPORTANT: Run from zkapp directory where node_modules is
            result = subprocess.run(
                ['sh', '-c', f'cd /app/zkapp && node build/generate_proof.js \'{json.dumps(proof_input)}\''],
                capture_output=True,
                text=True,
                timeout=1500 
            )
            
            if result.returncode != 0:
                logger.error(f"Proof generation failed: {result.stderr}")
                # Fallback to simulated proof
                return self.generate_simulated_proof(packet)
            
            # Parse proof output
            proof_output = json.loads(result.stdout)
            generation_time = time.time() - start_time
            
            logger.info(f"OK Real ZK proof generated in {generation_time*1000:.2f}ms")
            logger.info(f"  Proof size: {proof_output['proofSize']} bytes")
            
            return json.dumps(proof_output)
            
        except subprocess.TimeoutExpired:
            logger.warning("Proof generation timeout - using simulated proof")
            return self.generate_simulated_proof(packet)
        except Exception as e:
            logger.error(f"Error generating proof: {e}")
            return self.generate_simulated_proof(packet)
    
    def generate_simulated_proof(self, packet: Packet) -> str:
        """Fallback simulated proof for testing"""
        proof_data = {
            "uid": packet.uid,
            "sid": packet.sid,
            "data_hash": packet.data_hash,
            "timestamp": packet.timestamp,
            "proof_type": "simulated",
            "generated_at": time.time()
        }
        return json.dumps(proof_data)
    
    def connect_to_radio(self):
        """Setup UDP socket to receive from RadioA"""
        try:
            self.radio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.radio_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.radio_socket.bind((self.radio_host, self.radio_port))
            logger.info(f"Listening for RadioA on UDP {self.radio_host}:{self.radio_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to RadioA: {e}")
            return False
    
    def receive_from_radio(self):
        """Thread: Receive data from RadioA via UDP"""
        logger.info("Starting RadioA receiver thread...")
        
        if not self.connect_to_radio():
            logger.error("Cannot start without RadioA connection")
            return
        
        while True:
            try:
                # Receive UDP packet from RadioA
                data, addr = self.radio_socket.recvfrom(4096)
                
                message = data.decode('utf-8').strip()
                logger.info(f"Received from RadioA ({addr}): {message}")
                
                # Create packet
                packet = Packet.create(
                    uid=self.uid_counter,
                    sid=self.node_id,
                    data=message
                )
                self.uid_counter += 1
                
                # Generate ZK proof
                packet.zk_proof = self.generate_zk_proof(packet)
                
                # Add to queue for processing
                self.packet_queue.add(packet)
                logger.info(f"Created {packet}")
                
            except Exception as e:
                logger.error(f"Error receiving from RadioA: {e}")
                time.sleep(1)
    
    def forward_to_network(self):
        """Thread: Forward packets to first repeater"""
        logger.info("Starting packet forwarding thread...")
        
        while True:
            packet = self.packet_queue.get(timeout=1.0)
            if packet is None:
                continue
            
            try:
                # Connect to first repeater
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.next_host, self.next_port))
                
                # Send packet
                sock.sendall(packet.to_bytes())
                logger.info(f"Forwarded {packet} to {self.next_host}:{self.next_port}")
                
                # Wait for acknowledgment
                ack = sock.recv(1024)
                if ack == b'ACK':
                    logger.info(f"Packet {packet.uid} acknowledged by repeater")
                    self.stats.record_verified(packet, 0)
                else:
                    logger.warning(f"Packet {packet.uid} not acknowledged")
                
                sock.close()
                
            except Exception as e:
                logger.error(f"Error forwarding packet: {e}")
                self.stats.record_dropped("network_error")
                time.sleep(1)
    
    def start(self):
        """Start the producer node"""
        logger.info("="*60)
        logger.info("PRODUCER NODE STARTING")
        logger.info("="*60)
        
        # Start threads
        radio_thread = Thread(target=self.receive_from_radio, daemon=True)
        forward_thread = Thread(target=self.forward_to_network, daemon=True)
        
        radio_thread.start()
        forward_thread.start()
        
        logger.info("All threads started. Producer node is running.")
        logger.info("Waiting for data from RadioA...")
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(10)
                # Print periodic stats
                if self.stats.total_packets > 0:
                    logger.info(f"Stats: {self.stats.verified_packets} verified, {self.stats.dropped_packets} dropped")
        except KeyboardInterrupt:
            logger.info("Shutting down producer node...")
            self.stats.print_summary()


def main():
    producer = ProducerNode()
    producer.start()


if __name__ == "__main__":
    main()