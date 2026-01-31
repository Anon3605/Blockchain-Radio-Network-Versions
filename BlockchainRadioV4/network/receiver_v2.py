#!/usr/bin/env python3
"""
Receiver Node V2 - Blockchain Radio V4

The Receiver is the final node before RadioB:
  • Participates in blockchain consensus (like repeaters)
  • Verifies HMAC on incoming packets
  • Sends verified messages to RadioB via UDP

Same lightweight requirements as repeaters (Raspberry Pi capable).
"""

import os
import sys
import socket
import struct
import threading
import time
import json
import hashlib
import logging
from typing import Dict, Optional

# Imports from /app (PYTHONPATH is set to /app in Docker)
from blockchain.consensus import (
    SessionRecord, BlockProposal, Block, RepeaterSignature,
    BlockchainStorage, RepeaterNode,
    MSG_PROPOSAL, MSG_SIGNATURE, MSG_FINALIZED,
    pack_message, unpack_message
)
from crypto.hmac_auth import HMACAuth
from crypto.key_derivation import derive_session_key
from session.cache import SessionCache, CachedSession

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class ReceiverV2:
    """
    Receiver node - final hop before RadioB.
    
    Like a repeater, but instead of forwarding to another repeater,
    it sends to RadioB via UDP.
    """
    
    def __init__(self):
        # Configuration from environment
        self.node_id = os.environ.get('NODE_ID', 'receiver')
        self.data_listen_port = int(os.environ.get('DATA_LISTEN_PORT', 6000))
        self.radio_b_host = os.environ.get('RADIO_B_HOST', 'radio-b')
        self.radio_b_port = int(os.environ.get('RADIO_B_PORT', 54321))
        self.gossip_listen_port = int(os.environ.get('GOSSIP_LISTEN_PORT', 7000))
        
        # Blockchain storage
        os.makedirs('/app/data', exist_ok=True)
        self.storage = BlockchainStorage(f'/app/data/blockchain_{self.node_id}.json')
        
        # Receiver acts like a repeater for consensus
        self.repeater_node = RepeaterNode(self.node_id, self.storage)
        
        # Session cache
        self.session_cache = SessionCache(self.node_id)
        
        # Minimum signatures needed
        self.min_signatures = 3
        
        # UDP socket for sending to RadioB
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Stats
        self.packets_received = 0
        self.packets_verified = 0
        self.packets_delivered = 0
        
        # Threading
        self.running = False
        
        logger.info(f"ReceiverV2 initialized")
        logger.info(f"  Node ID: {self.node_id}")
        logger.info(f"  Blockchain port: {self.gossip_listen_port}")
        logger.info(f"  Data port: {self.data_listen_port}")
        logger.info(f"  RadioB: {self.radio_b_host}:{self.radio_b_port}")
    
    def cache_session_from_record(self, session: SessionRecord):
        """Cache a session for fast HMAC verification"""
        hmac_key = derive_session_key(
            session.commitment.encode(),
            session.public_key.encode(),
            session.session_id.encode()
        )
        
        self.session_cache.add_session(
            session_id=session.session_id,
            node_id=session.radio_id,
            peer_node_id=self.node_id,
            hmac_key=hmac_key,
            proof_hash=bytes.fromhex(session.proof_hash),
            zk_commitment=bytes.fromhex(session.commitment)
        )
        
        logger.info(f"Cached session {session.session_id[:16]}... proof_hash={session.proof_hash[:16]}...")
    
    def handle_blockchain_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming blockchain message"""
        try:
            result = unpack_message(conn, timeout=30.0)
            if result is None:
                return
            
            msg_type, data = result
            
            if msg_type == MSG_PROPOSAL:
                proposal = BlockProposal.from_bytes(data)
                logger.info(f"Received proposal for block #{proposal.number}")
                
                signature = self.repeater_node.sign_proposal(proposal)
                
                if signature:
                    sig_data = json.dumps(signature.to_dict()).encode()
                    conn.sendall(pack_message(MSG_SIGNATURE, sig_data))
                    logger.info(f"Signed proposal for block #{proposal.number}")
                else:
                    logger.warning(f"Rejected proposal for block #{proposal.number}")
            
            elif msg_type == MSG_FINALIZED:
                block = Block.from_bytes(data)
                logger.info(f"Received finalized block #{block.number}")
                
                if self.repeater_node.receive_finalized_block(block, min(self.min_signatures, len(block.signatures))):
                    logger.info(f"Stored block #{block.number}")
                    
                    for session in block.sessions:
                        self.cache_session_from_record(session)
                else:
                    logger.warning(f"Rejected block #{block.number}")
        
        except Exception as e:
            logger.error(f"Blockchain error: {e}")
        finally:
            conn.close()
    
    def run_blockchain_listener(self):
        """Listen for blockchain messages"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.gossip_listen_port))
        sock.listen(10)
        sock.settimeout(1.0)
        
        logger.info(f"Blockchain listener on port {self.gossip_listen_port}")
        
        while self.running:
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=self.handle_blockchain_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Blockchain listener error: {e}")
        
        sock.close()
    
    def verify_and_deliver_packet(self, packet: bytes) -> bool:
        """Verify HMAC and deliver to RadioB"""
        self.packets_received += 1
        
        if len(packet) < 108:
            logger.warning(f"Packet too small: {len(packet)} bytes")
            return False
        
        # Parse packet
        session_id = packet[0:32].rstrip(b'\x00').decode('utf-8', errors='ignore')
        proof_hash = packet[32:64].hex()
        seq = struct.unpack('!I', packet[64:68])[0]
        timestamp = struct.unpack('!d', packet[68:76])[0]
        received_hmac = packet[76:108]
        data = packet[108:]
        
        # Get cached session
        cached = self.session_cache.get_session(session_id)
        
        if cached is None:
            # Try loading from storage
            stored = self.storage.get_session(session_id)
            if stored:
                self.cache_session_from_record(stored)
                cached = self.session_cache.get_session(session_id)
            
            if cached is None:
                logger.warning(f"Unknown session: {session_id[:16]}...")
                return False
        
        # Verify proof_hash (cached.proof_hash is bytes, packet proof_hash is hex)
        cached_proof_hash_hex = cached.proof_hash.hex()
        if cached_proof_hash_hex != proof_hash:
            logger.warning(f"proof_hash mismatch")
            return False
        
        # Verify HMAC directly (same computation as producer)
        hmac_data = packet[0:76] + data
        
        import hashlib
        import hmac as hmac_module
        try:
            # BLAKE2b with key (faster)
            h = hashlib.blake2b(hmac_data, key=cached.hmac_key, digest_size=32)
            expected_tag = h.digest()
        except (AttributeError, ValueError):
            # Fallback to HMAC-SHA256
            expected_tag = hmac_module.new(cached.hmac_key, hmac_data, hashlib.sha256).digest()
        
        if not hmac_module.compare_digest(received_hmac, expected_tag):
            logger.warning(f"HMAC verification failed")
            return False
        
        self.packets_verified += 1
        logger.info(f"✓ Verified packet seq={seq} from session {session_id[:16]}...")
        
        # Deliver to RadioB
        try:
            self.udp_socket.sendto(data, (self.radio_b_host, self.radio_b_port))
            self.packets_delivered += 1
            logger.info(f" Delivered to RadioB: {len(data)} bytes")
            return True
        except Exception as e:
            logger.error(f"Failed to deliver to RadioB: {e}")
            return False
    
    def handle_data_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming data packet"""
        try:
            conn.settimeout(30.0)
            
            length_data = conn.recv(4)
            if len(length_data) < 4:
                return
            
            length = struct.unpack('!I', length_data)[0]
            
            packet = b''
            while len(packet) < length:
                chunk = conn.recv(min(8192, length - len(packet)))
                if not chunk:
                    break
                packet += chunk
            
            if len(packet) == length:
                self.verify_and_deliver_packet(packet)
        
        except Exception as e:
            logger.error(f"Data error: {e}")
        finally:
            conn.close()
    
    def run_data_listener(self):
        """Listen for data packets"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.data_listen_port))
        sock.listen(10)
        sock.settimeout(1.0)
        
        logger.info(f"Data listener on port {self.data_listen_port}")
        
        while self.running:
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=self.handle_data_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Data listener error: {e}")
        
        sock.close()
    
    def print_stats(self):
        """Print statistics periodically"""
        while self.running:
            time.sleep(30)
            logger.info(f"Stats: received={self.packets_received} verified={self.packets_verified} delivered={self.packets_delivered}")
    
    def start(self):
        """Start the receiver"""
        self.running = True
        
        os.makedirs('/app/data', exist_ok=True)
        
        # Start listeners
        threading.Thread(target=self.run_blockchain_listener, daemon=True).start()
        threading.Thread(target=self.run_data_listener, daemon=True).start()
        threading.Thread(target=self.print_stats, daemon=True).start()
        
        logger.info("Receiver V2 started")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            logger.info("Shutting down...")
    
    def stop(self):
        """Stop the receiver"""
        self.running = False


if __name__ == '__main__':
    receiver = ReceiverV2()
    receiver.start()
