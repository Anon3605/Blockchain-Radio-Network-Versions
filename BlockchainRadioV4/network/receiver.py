#!/usr/bin/env python3
"""
Receiver Node for Blockchain Radio V4

Final node in the mesh network:
1. Receives verified packets from repeater chain
2. Performs final HMAC verification
3. Delivers data to RadioB via UDP

The receiver trusts that upstream nodes have verified the ZK proof,
but still performs HMAC verification for defense in depth.
"""

import socket
import sys
import os
import json
import time
import logging
import threading
import struct
from typing import Optional, Dict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.keys import KeyPair, generate_keypair, get_or_create_keypair
from crypto.hmac_auth import verify_hmac
from session.cache import SessionCache
from network.packet import (
    PacketType, SessionPacket, DataPacket,
    PacketStatistics, parse_packet
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[RECEIVER] %(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ReceiverNode:
    """
    Receiver Node - Final verification and delivery to RadioB
    """
    
    def __init__(
        self,
        node_id: str = "receiver",
        listen_port: int = 6000,
        radio_host: str = 'radio-b',
        radio_port: int = 54321,
        key_file: str = '/app/keys/receiver.json'
    ):
        self.node_id = node_id
        self.listen_port = listen_port
        self.radio_host = radio_host
        self.radio_port = radio_port
        
        # Load or create keys
        try:
            self.keypair = get_or_create_keypair(key_file, node_id)
        except Exception:
            self.keypair = generate_keypair(node_id)
        
        # Session cache for verification
        self.session_cache = SessionCache(
            node_id=node_id,
            max_sessions=10000
        )
        
        # Packet tracking
        self.stats = PacketStatistics()
        self.received_packets: Dict[int, DataPacket] = {}
        
        # Sockets
        self.server_socket: Optional[socket.socket] = None
        self.radio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Threading
        self.running = False
        
        logger.info(f"Receiver Node initialized")
        logger.info(f"Listening on port {listen_port}")
        logger.info(f"Delivering to RadioB at {radio_host}:{radio_port}")
    
    def final_verification(self, packet: DataPacket) -> tuple[bool, str, float]:
        """
        Perform final verification before delivery
        
        This is defense-in-depth - upstream nodes already verified,
        but we check again to detect any tampering in transit.
        """
        start_time = time.time()
        
        # Step 1: Data integrity
        if not packet.verify_integrity():
            return False, "Data integrity failed", time.time() - start_time
        
        # Step 2: Get cached session
        cached = self.session_cache.get_session(packet.session_id)
        
        if cached is None:
            # Auto-cache for testing
            if os.getenv('AUTO_CACHE_SESSIONS', 'true').lower() == 'true':
                self._auto_cache_session(packet)
                cached = self.session_cache.get_session(packet.session_id)
            
            if cached is None:
                return False, "Session not found", time.time() - start_time
        
        # Step 3: Verify HMAC
        valid = verify_hmac(
            cached.hmac_key,
            packet.data,
            packet.hmac_tag,
            packet.session_id
        )
        
        verify_time = time.time() - start_time
        
        if valid:
            cached.record_verification(True, packet.sequence)
            return True, "OK", verify_time
        else:
            cached.record_verification(False, packet.sequence)
            return False, "HMAC verification failed", verify_time
    
    def _auto_cache_session(self, packet: DataPacket) -> None:
        """Auto-cache session for testing"""
        import hashlib
        fake_commitment = hashlib.sha256(packet.session_id.encode()).digest()
        fake_hmac_key = hashlib.sha256(b'test-key:' + packet.session_id.encode()).digest()
        
        self.session_cache.add_session(
            session_id=packet.session_id,
            node_id=f"node-{packet.sid}",
            peer_node_id="producer",
            hmac_key=fake_hmac_key,
            zk_commitment=fake_commitment
        )
    
    def deliver_to_radio_b(self, packet: DataPacket) -> bool:
        """Deliver verified data to RadioB via UDP"""
        try:
            # Format message
            message = f"[Packet {packet.uid}] {packet.data.decode('utf-8', errors='replace')}"
            
            self.radio_socket.sendto(
                message.encode('utf-8'),
                (self.radio_host, self.radio_port)
            )
            
            logger.info(f"📡 Delivered to RadioB: {message[:50]}...")
            
            # Record latency
            self.stats.record_latency(packet, time.time())
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver to RadioB: {e}")
            return False
    
    def setup_server(self) -> bool:
        """Setup server socket"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.listen_port))
            self.server_socket.listen(10)
            self.server_socket.settimeout(1.0)
            logger.info(f"Server listening on port {self.listen_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup server: {e}")
            return False
    
    def receive_and_deliver(self) -> None:
        """Thread: Receive packets, verify, and deliver"""
        logger.info("Starting receiver thread...")
        
        if not self.setup_server():
            return
        
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                conn.settimeout(10.0)
                
                # Receive packet length
                length_data = conn.recv(4)
                if len(length_data) < 4:
                    conn.close()
                    continue
                
                packet_len = struct.unpack('!I', length_data)[0]
                
                # Receive packet data
                data = b''
                while len(data) < packet_len:
                    chunk = conn.recv(min(8192, packet_len - len(data)))
                    if not chunk:
                        break
                    data += chunk
                
                if len(data) < packet_len:
                    conn.close()
                    continue
                
                # Parse packet
                packet = parse_packet(data)
                
                if isinstance(packet, DataPacket):
                    logger.info(f"Received {packet} (hops: {packet.hop_count})")
                    
                    # Check for duplicate
                    if packet.uid in self.received_packets:
                        logger.info(f"Duplicate packet {packet.uid} - ignoring")
                        self.stats.record_dropped("duplicate")
                        conn.send(b'DUP')
                        conn.close()
                        continue
                    
                    # Final verification
                    valid, reason, verify_time = self.final_verification(packet)
                    
                    if valid:
                        # Store packet
                        self.received_packets[packet.uid] = packet
                        
                        # Deliver to RadioB
                        if self.deliver_to_radio_b(packet):
                            conn.send(b'ACK')
                            logger.info(
                                f"✓ Packet {packet.uid} verified ({verify_time*1000:.3f}ms) "
                                f"and delivered"
                            )
                            self.stats.record_data_packet(packet, verify_time)
                        else:
                            conn.send(b'DELIVERY_FAILED')
                            logger.error(f"✗ Delivery failed for packet {packet.uid}")
                    else:
                        conn.send(b'FAIL')
                        logger.warning(f"✗ Packet {packet.uid} rejected: {reason}")
                        self.stats.record_dropped("verification_failed")
                
                conn.close()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error: {e}")
                    import traceback
                    traceback.print_exc()
    
    def start(self) -> None:
        """Start the receiver node"""
        logger.info("=" * 60)
        logger.info("RECEIVER NODE STARTING")
        logger.info("=" * 60)
        
        self.running = True
        
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_and_deliver, daemon=True)
        receiver_thread.start()
        
        logger.info("Receiver ready for packets")
        
        # Main loop
        try:
            while self.running:
                time.sleep(10)
                
                if self.stats.total_packets > 0:
                    summary = self.stats.get_summary()
                    logger.info(
                        f"Stats: {summary['verified_packets']} delivered, "
                        f"{summary['dropped_packets']} dropped, "
                        f"avg latency: {summary['avg_latency_ms']:.2f}ms"
                    )
                    
        except KeyboardInterrupt:
            logger.info("Shutting down receiver...")
            self.shutdown()
    
    def shutdown(self) -> None:
        """Shutdown the node"""
        self.running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        self.session_cache.shutdown()
        self.stats.print_summary()


def main():
    receiver = ReceiverNode()
    receiver.start()


if __name__ == "__main__":
    main()
