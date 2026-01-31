#!/usr/bin/env python3
"""
Repeater Node V2 - Blockchain Radio V4

Integrates:
  • Block proposal verification and signing (consensus participation)
  • Finalized block storage and session caching
  • Data packet forwarding with HMAC verification

The Repeater is LIGHTWEIGHT (Raspberry Pi):
  • Verifies block proposals (~0.2ms)
  • Signs proposals (~1ms)
  • Caches sessions for fast lookup
  • Verifies HMAC on packets (~3µs)
  • Forwards packets to next hop

THE REPEATERS RUN THE BLOCKCHAIN by deciding to sign proposals.
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
from typing import Dict, Optional, Tuple

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


class RepeaterV2:
    """
    Repeater node with consensus-based blockchain.
    
    Two listeners:
      1. Blockchain port (7000): Receive proposals, send signatures, receive finalized blocks
      2. Data port (5xxx): Receive packets, verify HMAC, forward to next hop
    """
    
    def __init__(self):
        # Configuration from environment
        self.node_id = os.environ.get('NODE_ID', 'repeater')
        self.data_listen_port = int(os.environ.get('DATA_LISTEN_PORT', 5001))
        self.data_next_hop = os.environ.get('DATA_NEXT_HOP', 'repeater2:5002')
        self.gossip_listen_port = int(os.environ.get('GOSSIP_LISTEN_PORT', 7000))
        
        # Parse next hop
        hop_parts = self.data_next_hop.split(':')
        self.next_hop_host = hop_parts[0]
        self.next_hop_port = int(hop_parts[1]) if len(hop_parts) > 1 else 5002
        
        # Blockchain storage
        os.makedirs('/app/data', exist_ok=True)
        self.storage = BlockchainStorage(f'/app/data/blockchain_{self.node_id}.json')
        
        # Repeater node (handles signing)
        self.repeater_node = RepeaterNode(self.node_id, self.storage)
        
        # Session cache for fast HMAC verification
        self.session_cache = SessionCache(self.node_id)
        
        # Minimum signatures needed (will be updated from producer's proposals)
        self.min_signatures = 3
        
        # Threading
        self.running = False
        
        logger.info(f"RepeaterV2 initialized")
        logger.info(f"  Node ID: {self.node_id}")
        logger.info(f"  Blockchain port: {self.gossip_listen_port}")
        logger.info(f"  Data port: {self.data_listen_port}")
        logger.info(f"  Next hop: {self.next_hop_host}:{self.next_hop_port}")
    
    def cache_session_from_record(self, session: SessionRecord):
        """Cache a session for fast HMAC verification"""
        # Derive HMAC key
        hmac_key = derive_session_key(
            session.commitment.encode(),
            session.public_key.encode(),
            session.session_id.encode()
        )
        
        # Add to cache
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
        """Handle incoming blockchain message (proposal or finalized block)"""
        try:
            result = unpack_message(conn, timeout=30.0)
            if result is None:
                return
            
            msg_type, data = result
            
            if msg_type == MSG_PROPOSAL:
                # Verify and sign proposal
                proposal = BlockProposal.from_bytes(data)
                logger.info(f"Received proposal for block #{proposal.number} from {addr}")
                
                # Sign if valid
                signature = self.repeater_node.sign_proposal(proposal)
                
                if signature:
                    # Send signature back
                    sig_data = json.dumps(signature.to_dict()).encode()
                    conn.sendall(pack_message(MSG_SIGNATURE, sig_data))
                    logger.info(f"Signed and returned signature for block #{proposal.number}")
                else:
                    logger.warning(f"Rejected invalid proposal for block #{proposal.number}")
            
            elif msg_type == MSG_FINALIZED:
                # Store finalized block and cache sessions
                block = Block.from_bytes(data)
                logger.info(f"Received finalized block #{block.number} with {len(block.signatures)} signatures")
                
                if self.repeater_node.receive_finalized_block(block, min(self.min_signatures, len(block.signatures))):
                    logger.info(f"Stored finalized block #{block.number}")
                    
                    # Cache all sessions from this block
                    for session in block.sessions:
                        self.cache_session_from_record(session)
                else:
                    logger.warning(f"Rejected invalid finalized block #{block.number}")
        
        except Exception as e:
            logger.error(f"Blockchain connection error: {e}")
        finally:
            conn.close()
    
    def run_blockchain_listener(self):
        """Listen for blockchain messages (proposals, finalized blocks)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.gossip_listen_port))
        sock.listen(10)
        sock.settimeout(1.0)
        
        logger.info(f"Blockchain listener started on port {self.gossip_listen_port}")
        
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
    
    def verify_and_forward_packet(self, packet: bytes) -> bool:
        """
        Verify HMAC and forward packet to next hop.
        
        Packet format:
          [session_id (32)] [proof_hash (32)] [seq (4)] [timestamp (8)] [hmac (32)] [data]
        """
        if len(packet) < 108:  # Minimum packet size
            logger.warning(f"Packet too small: {len(packet)} bytes")
            return False
        
        # Parse packet
        session_id = packet[0:32].rstrip(b'\x00').decode('utf-8', errors='ignore')
        proof_hash = packet[32:64].hex()
        seq = struct.unpack('!I', packet[64:68])[0]
        timestamp = struct.unpack('!d', packet[68:76])[0]
        received_hmac = packet[76:108]
        data = packet[108:]
        
        logger.debug(f"Packet: session={session_id[:16]}... seq={seq} proof_hash={proof_hash[:16]}...")
        
        # Get cached session
        cached = self.session_cache.get_session(session_id)
        
        if cached is None:
            logger.warning(f"Unknown session: {session_id[:16]}...")
            # Try to load from blockchain storage
            stored_session = self.storage.get_session(session_id)
            if stored_session:
                self.cache_session_from_record(stored_session)
                cached = self.session_cache.get_session(session_id)
            
            if cached is None:
                logger.error(f"Session not found in storage either")
                return False
        
        # Verify proof_hash matches (cached.proof_hash is bytes, packet proof_hash is hex)
        cached_proof_hash_hex = cached.proof_hash.hex()
        if cached_proof_hash_hex != proof_hash:
            logger.warning(f"proof_hash mismatch: expected {cached_proof_hash_hex[:16]}... got {proof_hash[:16]}...")
            return False
        
        # Verify HMAC directly (same computation as producer)
        # HMAC is over: session_id || proof_hash || seq || timestamp || data
        hmac_data = packet[0:76] + data  # Everything except the HMAC tag itself
        
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
            logger.warning(f"HMAC verification failed for session {session_id[:16]}... seq={seq}")
            return False
        
        logger.info(f"✓ Verified packet: session={session_id[:16]}... seq={seq}")
        
        # Forward to next hop
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.next_hop_host, self.next_hop_port))
            
            # Forward entire packet unchanged
            sock.sendall(struct.pack('!I', len(packet)) + packet)
            sock.close()
            
            logger.debug(f"Forwarded to {self.next_hop_host}:{self.next_hop_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to forward packet: {e}")
            return False
    
    def handle_data_connection(self, conn: socket.socket, addr: tuple):
        """Handle incoming data packet"""
        try:
            conn.settimeout(30.0)
            
            # Read length
            length_data = conn.recv(4)
            if len(length_data) < 4:
                return
            
            length = struct.unpack('!I', length_data)[0]
            
            # Read packet
            packet = b''
            while len(packet) < length:
                chunk = conn.recv(min(8192, length - len(packet)))
                if not chunk:
                    break
                packet += chunk
            
            if len(packet) == length:
                self.verify_and_forward_packet(packet)
        
        except Exception as e:
            logger.error(f"Data connection error: {e}")
        finally:
            conn.close()
    
    def run_data_listener(self):
        """Listen for data packets to verify and forward"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.data_listen_port))
        sock.listen(10)
        sock.settimeout(1.0)
        
        logger.info(f"Data listener started on port {self.data_listen_port}")
        
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
    
    def start(self):
        """Start the repeater"""
        self.running = True
        
        # Ensure data directory exists
        os.makedirs('/app/data', exist_ok=True)
        
        # Start blockchain listener
        blockchain_thread = threading.Thread(target=self.run_blockchain_listener, daemon=True)
        blockchain_thread.start()
        
        # Start data listener
        data_thread = threading.Thread(target=self.run_data_listener, daemon=True)
        data_thread.start()
        
        logger.info("Repeater V2 started")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            logger.info("Shutting down...")
    
    def stop(self):
        """Stop the repeater"""
        self.running = False


if __name__ == '__main__':
    repeater = RepeaterV2()
    repeater.start()
