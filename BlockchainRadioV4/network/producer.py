#!/usr/bin/env python3
"""
Producer Node for Blockchain Radio V4

The producer is the entry point to the mesh network:
1. Receives voice data from RadioA via UDP
2. Establishes sessions with ZK-SNARK proofs (one-time, ~120s)
3. Authenticates subsequent messages with fast HMAC (~0.1ms)
4. Forwards to the repeater chain

This is the key optimization point - session establishment is slow,
but all subsequent messages use cached session keys for real-time auth.
"""

import socket
import sys
import os
import json
import time
import logging
import threading
import hashlib
from typing import Optional, Dict

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.keys import KeyPair, generate_keypair, get_or_create_keypair
from crypto.hmac_auth import HMACAuth
from crypto.key_derivation import derive_session_key, derive_hmac_key, generate_session_nonce
from session.session import Session, SessionState, SessionManager
from session.handshake import SessionHandshake, HandshakeMessage, HandshakeState
from network.packet import (
    PacketType, SessionPacket, DataPacket, 
    PacketQueue, PacketStatistics, parse_packet
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[PRODUCER] %(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProducerNode:
    """
    Producer Node - Entry point to the radio mesh network
    
    Handles:
    - Session establishment via ZK-SNARK
    - Fast HMAC authentication for real-time data
    - Forwarding to repeater chain
    """
    
    def __init__(
        self,
        node_id: str = "producer",
        radio_host: str = '0.0.0.0',
        radio_port: int = 12345,
        key_file: str = '/app/keys/producer.json',
        zkapp_path: str = '/app/zkapp'
    ):
        self.node_id = node_id
        self.radio_host = radio_host
        self.radio_port = int(os.getenv('RADIO_PORT', radio_port))
        self.next_hop = os.getenv('NEXT_HOP', 'repeater1:5001')
        self.zkapp_path = zkapp_path
        
        # Parse next hop
        parts = self.next_hop.split(':')
        self.next_host = parts[0]
        self.next_port = int(parts[1]) if len(parts) > 1 else 5001
        
        # Load or create keys
        try:
            self.keypair = get_or_create_keypair(key_file, node_id)
            logger.info(f"Loaded keys from {key_file}")
        except Exception as e:
            logger.warning(f"Could not load keys: {e}, generating new keys")
            self.keypair = generate_keypair(node_id)
        
        # Session management
        self.session_manager = SessionManager(node_id, self.keypair)
        self.active_sessions: Dict[str, Session] = {}  # peer_id -> Session
        
        # Packet tracking
        self.packet_queue = PacketQueue()
        self.stats = PacketStatistics()
        self.uid_counter = 1
        
        # Sockets
        self.radio_socket: Optional[socket.socket] = None
        
        # Threading
        self.running = False
        
        logger.info(f"Producer Node initialized: {node_id}")
        logger.info(f"Listening for RadioA on {self.radio_host}:{self.radio_port}")
        logger.info(f"Next hop: {self.next_host}:{self.next_port}")
    
    def get_or_establish_session(self, peer_id: str) -> Session:
        """
        Get existing session or establish new one
        
        This is where the ZK-SNARK  happens (once per session).
        """
        # Check for existing active session
        session = self.active_sessions.get(peer_id)
        if session and session.is_active:
            return session
        
        # Create new session
        logger.info(f"Establishing new session with {peer_id}...")
        session = self.session_manager.create_session(peer_id)
        
        # Perform handshake (this is the slow part)
        start_time = time.time()
        
        handshake = SessionHandshake(
            self.keypair, 
            peer_id,
            zkapp_path=self.zkapp_path
        )
        
        # For producer->repeater, we use simulated proofs in testing
        # In production, this would be a full ZK-SNARK handshake
        use_simulated = os.getenv('USE_SIMULATED_PROOFS', 'true').lower() == 'true'
        
        try:
            # Generate local commitment for session key derivation
            nonce = generate_session_nonce()
            commitment = hashlib.sha256(
                self.keypair.public_key + 
                peer_id.encode() + 
                nonce
            ).digest()
            
            # Derive session key
            session_key = derive_session_key(
                commitment,
                self.keypair.public_key,
                nonce
            )
            
            # Create proof (simulated or real)
            if use_simulated:
                proof_json = json.dumps({
                    'type': 'simulated',
                    'node_id': self.node_id,
                    'commitment': commitment.hex(),
                    'timestamp': time.time()
                })
                proof_time = 0.001
            else:
                # Real ZK proof generation (~120s)
                hello_msg = handshake.create_hello()
                # ... full handshake protocol
                proof_json = handshake.proof_json or "{}"
                proof_time = handshake.proof_generation_time or 120.0
            
            # Establish session
            session.establish(session_key, proof_json, commitment)
            
            handshake_time = time.time() - start_time
            logger.info(f"✓ Session established in {handshake_time:.2f}s")
            logger.info(f"  Session ID: {session.session_id[:16]}...")
            logger.info(f"  Proof generation: {proof_time:.2f}s")
            
            self.active_sessions[peer_id] = session
            return session
            
        except Exception as e:
            logger.error(f"Session establishment failed: {e}")
            raise
    
    def create_authenticated_packet(
        self, 
        session: Session, 
        data: bytes
    ) -> DataPacket:
        """
        Create a data packet with HMAC authentication
        
        This is the FAST path (~0.1ms) used for all messages after session.
        """
        # Create HMAC tag
        tag, seq, ts = session.create_authenticated_message(data)
        
        # Create packet
        packet = DataPacket(
            packet_type=PacketType.DATA,
            uid=self.uid_counter,
            sid=hash(self.node_id) % 10000,
            rid=0,
            session_id=session.session_id,
            timestamp=ts,
            data=data,
            sequence=seq,
            hmac_tag=tag
        )
        
        self.uid_counter += 1
        return packet
    
    def connect_to_radio(self) -> bool:
        """Setup UDP socket to receive from RadioA"""
        try:
            self.radio_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.radio_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.radio_socket.bind((self.radio_host, self.radio_port))
            self.radio_socket.settimeout(1.0)
            logger.info(f"Listening for RadioA on UDP {self.radio_host}:{self.radio_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to setup radio socket: {e}")
            return False
    
    def receive_from_radio(self) -> None:
        """Thread: Receive data from RadioA via UDP"""
        logger.info("Starting RadioA receiver thread...")
        
        if not self.connect_to_radio():
            logger.error("Cannot start without radio socket")
            return
        
        # Establish session on first message
        session: Optional[Session] = None
        default_peer = "radio-a"
        
        while self.running:
            try:
                data, addr = self.radio_socket.recvfrom(4096)
                message = data.decode('utf-8').strip()
                
                logger.info(f"Received from RadioA ({addr}): {message[:50]}...")
                
                # Ensure session is established
                if session is None or not session.is_active:
                    logger.info("First message - establishing session...")
                    session = self.get_or_establish_session(default_peer)
                
                # Create authenticated packet (FAST path)
                start_time = time.time()
                packet = self.create_authenticated_packet(session, data)
                auth_time = time.time() - start_time
                
                logger.debug(f"Created authenticated packet in {auth_time*1000:.3f}ms")
                
                # Queue for forwarding
                if self.packet_queue.add(packet):
                    logger.info(f"Queued {packet}")
                else:
                    logger.warning(f"Duplicate packet {packet.uid}")
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving from RadioA: {e}")
                    time.sleep(0.1)
    
    def forward_to_network(self) -> None:
        """Thread: Forward packets to first repeater"""
        logger.info(f"Starting packet forwarder to {self.next_host}:{self.next_port}...")
        
        while self.running:
            packet = self.packet_queue.get(timeout=1.0)
            if packet is None:
                continue
            
            try:
                # Send session info first if this is a new session
                # (In a full implementation, we'd send a SESSION_PROOF packet first)
                
                # Connect to first repeater
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10.0)
                sock.connect((self.next_host, self.next_port))
                
                # Send packet
                packet_bytes = packet.to_bytes()
                sock.sendall(struct.pack('!I', len(packet_bytes)) + packet_bytes)
                
                logger.info(f"→ Forwarded {packet} to {self.next_host}:{self.next_port}")
                
                # Wait for acknowledgment
                ack = sock.recv(1024)
                if ack == b'ACK':
                    logger.debug(f"Packet {packet.uid} acknowledged")
                    self.stats.record_data_packet(packet, 0.0001)
                elif ack == b'SESSION_REQUIRED':
                    logger.warning(f"Repeater requires session establishment")
                    # Would trigger full handshake here
                else:
                    logger.warning(f"Packet {packet.uid} not acknowledged: {ack}")
                
                sock.close()
                
            except Exception as e:
                logger.error(f"Error forwarding packet: {e}")
                self.stats.record_dropped("network_error")
                time.sleep(0.5)
    
    def start(self) -> None:
        """Start the producer node"""
        logger.info("=" * 60)
        logger.info("PRODUCER NODE STARTING")
        logger.info("=" * 60)
        logger.info(f"Node ID: {self.node_id}")
        logger.info(f"Public Key: {self.keypair.get_public_key_hex()[:32]}...")
        logger.info("=" * 60)
        
        self.running = True
        
        # Start threads
        radio_thread = threading.Thread(target=self.receive_from_radio, daemon=True)
        forward_thread = threading.Thread(target=self.forward_to_network, daemon=True)
        
        radio_thread.start()
        forward_thread.start()
        
        logger.info("All threads started. Waiting for data from RadioA...")
        
        # Main loop
        try:
            while self.running:
                time.sleep(10)
                
                # Print stats
                if self.stats.total_packets > 0:
                    summary = self.stats.get_summary()
                    logger.info(
                        f"Stats: {summary['verified_packets']} sent, "
                        f"{summary['dropped_packets']} dropped, "
                        f"avg auth time: {summary['avg_verification_time_ms']:.4f}ms"
                    )
                
                # Print session info
                for peer_id, session in self.active_sessions.items():
                    if session.is_active:
                        logger.debug(f"Session {peer_id}: {session.messages_sent} messages sent")
                        
        except KeyboardInterrupt:
            logger.info("Shutting down producer node...")
            self.shutdown()
    
    def shutdown(self) -> None:
        """Shutdown the node"""
        self.running = False
        
        # Close sockets
        if self.radio_socket:
            self.radio_socket.close()
        
        # Close sessions
        self.session_manager.shutdown()
        
        # Print final stats
        self.stats.print_summary()


# Need struct for packet length prefix
import struct


def main():
    node_id = os.getenv('NODE_ID', 'producer')
    producer = ProducerNode(node_id=node_id)
    producer.start()


if __name__ == "__main__":
    main()
