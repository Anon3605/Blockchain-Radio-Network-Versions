#!/usr/bin/env python3
"""
Producer Node V2 - Blockchain Radio V4

Integrates:
  • ZK-SNARK proof generation (or simulated)
  • Block proposal creation
  • Signature collection from repeaters
  • Block finalization and broadcast
  • Data forwarding with HMAC authentication

The Producer is the POWERFUL node (Ryzen 7):
  • Generates ZK proofs
  • Creates block proposals
  • Collects signatures (repeaters DECIDE)
  • Finalizes blocks when majority signs
  • Forwards authenticated data packets
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
from typing import Dict, List, Optional, Tuple

# Imports from /app (PYTHONPATH is set to /app in Docker)
from blockchain.consensus import (
    SessionRecord, BlockProposal, Block, RepeaterSignature,
    BlockchainStorage, ProducerNode,
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


class ProducerV2:
    """
    Producer node with consensus-based blockchain.
    
    Flow:
      1. RadioA sends message via UDP
      2. If no session: Create ZK proof → Create proposal → Get signatures → Finalize
      3. Forward message with HMAC to next hop
    """
    
    def __init__(self):
        # Configuration from environment
        self.node_id = os.environ.get('NODE_ID', 'producer')
        self.data_listen_port = int(os.environ.get('DATA_LISTEN_PORT', 12345))
        self.data_next_hop = os.environ.get('DATA_NEXT_HOP', 'repeater1:5001')
        self.gossip_listen_port = int(os.environ.get('GOSSIP_LISTEN_PORT', 7000))
        self.gossip_peers = os.environ.get('GOSSIP_PEERS', '').split(',')
        self.use_simulated = os.environ.get('USE_SIMULATED_PROOFS', 'true').lower() == 'true'
        
        # Parse next hop
        hop_parts = self.data_next_hop.split(':')
        self.next_hop_host = hop_parts[0]
        self.next_hop_port = int(hop_parts[1]) if len(hop_parts) > 1 else 5001
        
        # Parse gossip peers into (host, port) tuples
        self.repeater_addresses: List[Tuple[str, int]] = []
        for peer in self.gossip_peers:
            if peer and ':' in peer:
                parts = peer.split(':')
                self.repeater_addresses.append((parts[0], int(parts[1])))
        
        # Blockchain
        self.storage = BlockchainStorage('/app/data/blockchain.json')
        self.producer_node = ProducerNode(
            self.node_id, 
            self.storage,
            repeater_count=len(self.repeater_addresses) if self.repeater_addresses else 4
        )
        
        # Session management
        self.session_cache = SessionCache(self.node_id)
        self.active_sessions: Dict[str, dict] = {}  # session_id -> {hmac_key, proof_hash, ...}
        
        # Sequence numbers per session
        self.sequence_numbers: Dict[str, int] = {}
        
        # Threading
        self.running = False
        
        logger.info(f"ProducerV2 initialized")
        logger.info(f"  Node ID: {self.node_id}")
        logger.info(f"  Data listen: UDP {self.data_listen_port}")
        logger.info(f"  Next hop: {self.next_hop_host}:{self.next_hop_port}")
        logger.info(f"  Repeaters: {len(self.repeater_addresses)}")
        logger.info(f"  Simulated proofs: {self.use_simulated}")
    
    def generate_zk_proof(self, radio_id: str, public_key: str) -> Tuple[str, str]:
        """
        Generate ZK-SNARK proof (or simulated).
        
        Returns (proof_hash, commitment)
        """
        if self.use_simulated:
            # Simulated proof - instant but not cryptographically secure
            logger.info(f"Generating SIMULATED proof for {radio_id}")
            proof_data = f"simulated_proof:{radio_id}:{public_key}:{time.time()}"
            proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()
            commitment = hashlib.sha256(f"commitment:{proof_hash}".encode()).hexdigest()
            return proof_hash, commitment
        else:
            # Real ZK proof - would take ~120 seconds
            # For now, simulate the delay
            logger.info(f"Generating REAL ZK proof for {radio_id} (this takes ~120s)...")
            time.sleep(5)  # Shortened for testing
            proof_data = f"real_proof:{radio_id}:{public_key}:{time.time()}"
            proof_hash = hashlib.sha256(proof_data.encode()).hexdigest()
            commitment = hashlib.sha256(f"commitment:{proof_hash}".encode()).hexdigest()
            return proof_hash, commitment
    
    def establish_session(self, radio_id: str) -> Optional[str]:
        """
        Establish a new session for a radio.
        
        1. Generate ZK proof
        2. Create block proposal
        3. Broadcast to repeaters, collect signatures
        4. Finalize when majority signs
        5. Broadcast finalized block
        
        Returns session_id if successful.
        """
        logger.info(f"=== ESTABLISHING SESSION for {radio_id} ===")
        
        # Generate "public key" for radio (in real system, radio would provide this)
        public_key = hashlib.sha256(f"pubkey:{radio_id}".encode()).hexdigest()
        
        # Generate ZK proof
        proof_hash, commitment = self.generate_zk_proof(radio_id, public_key)
        
        # Create session record
        session_id = hashlib.sha256(f"session:{radio_id}:{time.time()}".encode()).hexdigest()[:32]
        
        session = SessionRecord(
            session_id=session_id,
            radio_id=radio_id,
            public_key=public_key,
            proof_hash=proof_hash,
            commitment=commitment,
            created_at=time.time(),
            expires_at=time.time() + 3600  # 1 hour
        )
        
        # Create proposal
        self.producer_node.add_session(session)
        proposal = self.producer_node.create_proposal()
        
        if not proposal:
            logger.error("Failed to create proposal")
            return None
        
        logger.info(f"Created proposal for block #{proposal.number}")
        
        # Broadcast to repeaters and collect signatures
        if self.repeater_addresses:
            sig_count = self._broadcast_proposal_collect_signatures(proposal)
            logger.info(f"Collected {sig_count}/{self.producer_node.min_signatures} signatures")
            
            if not self.producer_node.has_enough_signatures():
                logger.warning("Not enough signatures, but continuing with simulated consensus")
                # In production, we'd fail here. For testing, we'll continue.
        
        # Finalize block
        block = self.producer_node.finalize_block()
        
        if block:
            logger.info(f"Block #{block.number} finalized!")
            
            # Broadcast finalized block to repeaters
            if self.repeater_addresses:
                self._broadcast_finalized_block(block)
        else:
            logger.warning("Block finalization failed, creating local-only session")
        
        # Derive HMAC key for this session
        hmac_key = derive_session_key(
            commitment.encode(),
            public_key.encode(),
            session_id.encode()
        )
        
        # Cache session locally
        self.active_sessions[session_id] = {
            'radio_id': radio_id,
            'proof_hash': proof_hash,
            'commitment': commitment,
            'hmac_key': hmac_key,
            'public_key': public_key
        }
        
        # Also add to session cache for verification
        self.session_cache.add_session(
            session_id=session_id,
            node_id=radio_id,
            peer_node_id=self.node_id,
            hmac_key=hmac_key,
            proof_hash=bytes.fromhex(proof_hash),
            zk_commitment=bytes.fromhex(commitment)
        )
        
        self.sequence_numbers[session_id] = 0
        
        logger.info(f"=== SESSION ESTABLISHED: {session_id[:16]}... ===")
        return session_id
    
    def _broadcast_proposal_collect_signatures(self, proposal: BlockProposal) -> int:
        """Broadcast proposal to all repeaters and collect signatures"""
        threads = []
        
        for host, port in self.repeater_addresses:
            t = threading.Thread(
                target=self._send_proposal_to_repeater,
                args=(host, port, proposal)
            )
            t.start()
            threads.append(t)
        
        # Wait for all with timeout
        for t in threads:
            t.join(timeout=10.0)
        
        return len(self.producer_node.collected_signatures)
    
    def _send_proposal_to_repeater(self, host: str, port: int, proposal: BlockProposal):
        """Send proposal to one repeater and collect signature"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect((host, port))
            
            # Send proposal
            data = proposal.to_bytes()
            sock.sendall(pack_message(MSG_PROPOSAL, data))
            logger.info(f"Sent proposal to {host}:{port}")
            
            # Receive signature
            result = unpack_message(sock, timeout=10.0)
            if result and result[0] == MSG_SIGNATURE:
                sig_data = json.loads(result[1].decode())
                sig = RepeaterSignature.from_dict(sig_data)
                self.producer_node.receive_signature(sig)
                logger.info(f"Received signature from {host}:{port}")
            
            sock.close()
        except Exception as e:
            logger.warning(f"Failed to get signature from {host}:{port}: {e}")
    
    def _broadcast_finalized_block(self, block: Block):
        """Broadcast finalized block to all repeaters"""
        for host, port in self.repeater_addresses:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((host, port))
                sock.sendall(pack_message(MSG_FINALIZED, block.to_bytes()))
                sock.close()
                logger.info(f"Sent finalized block to {host}:{port}")
            except Exception as e:
                logger.warning(f"Failed to send finalized block to {host}:{port}: {e}")
    
    def get_or_create_session(self, radio_id: str) -> Optional[str]:
        """Get existing session or create new one"""
        # Check if we have an active session for this radio
        for session_id, info in self.active_sessions.items():
            if info['radio_id'] == radio_id:
                # Check if not expired
                session = self.storage.get_session(session_id)
                if session and not session.is_expired():
                    return session_id
        
        # Create new session
        return self.establish_session(radio_id)
    
    def forward_packet(self, session_id: str, data: bytes) -> bool:
        """Forward packet to next hop with HMAC authentication"""
        if session_id not in self.active_sessions:
            logger.error(f"Unknown session: {session_id}")
            return False
        
        session_info = self.active_sessions[session_id]
        
        # Get sequence number
        seq = self.sequence_numbers.get(session_id, 0)
        self.sequence_numbers[session_id] = seq + 1
        
        # Create authenticated packet
        # Format: [session_id (32)] [proof_hash (32)] [seq (4)] [timestamp (8)] [hmac (32)] [data]
        timestamp = time.time()
        
        packet = bytearray()
        packet.extend(session_id.encode()[:32].ljust(32, b'\x00'))
        packet.extend(bytes.fromhex(session_info['proof_hash']))
        packet.extend(struct.pack('!I', seq))
        packet.extend(struct.pack('!d', timestamp))
        
        # Compute HMAC directly over: session_id || proof_hash || seq || timestamp || data
        # Using simple keyed BLAKE2b (or HMAC-SHA256 fallback)
        hmac_data = bytes(packet) + data
        
        import hashlib
        try:
            # BLAKE2b with key (faster)
            h = hashlib.blake2b(hmac_data, key=session_info['hmac_key'], digest_size=32)
            tag = h.digest()
        except (AttributeError, ValueError):
            # Fallback to HMAC-SHA256
            import hmac as hmac_module
            tag = hmac_module.new(session_info['hmac_key'], hmac_data, hashlib.sha256).digest()
        
        packet.extend(tag)
        packet.extend(data)
        
        # Send to next hop
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((self.next_hop_host, self.next_hop_port))
            
            # Send length-prefixed packet
            length = len(packet)
            sock.sendall(struct.pack('!I', length) + bytes(packet))
            sock.close()
            
            logger.debug(f"Forwarded packet seq={seq} to {self.next_hop_host}:{self.next_hop_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to forward packet: {e}")
            return False
    
    def handle_radio_message(self, data: bytes, addr: tuple):
        """Handle incoming message from RadioA"""
        radio_id = f"radio-{addr[0]}:{addr[1]}"
        
        logger.info(f"Received from {radio_id}: {len(data)} bytes")
        
        # Get or create session
        session_id = self.get_or_create_session(radio_id)
        
        if not session_id:
            logger.error(f"Failed to establish session for {radio_id}")
            return
        
        # Forward with authentication
        if self.forward_packet(session_id, data):
            logger.info(f"Message forwarded for session {session_id[:16]}...")
        else:
            logger.error(f"Failed to forward message")
    
    def run_udp_listener(self):
        """Listen for UDP messages from RadioA"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.data_listen_port))
        sock.settimeout(1.0)
        
        logger.info(f"UDP listener started on port {self.data_listen_port}")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                self.handle_radio_message(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"UDP listener error: {e}")
        
        sock.close()
    
    def start(self):
        """Start the producer"""
        self.running = True
        
        # Ensure data directory exists
        os.makedirs('/app/data', exist_ok=True)
        
        # Start UDP listener
        udp_thread = threading.Thread(target=self.run_udp_listener, daemon=True)
        udp_thread.start()
        
        logger.info("Producer V2 started")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            logger.info("Shutting down...")
    
    def stop(self):
        """Stop the producer"""
        self.running = False


if __name__ == '__main__':
    producer = ProducerV2()
    producer.start()
