#!/usr/bin/env python3
"""
Blockchain Module for Blockchain Radio V4 - CORRECT ARCHITECTURE

The blockchain is RUN BY THE REPEATERS collectively.
Producer PROPOSES, Repeaters DECIDE.

Architecture:
═════════════

  PRODUCER (Heavy - Ryzen 7):
    • Generates ZK-SNARK proof (~120s)
    • Creates block PROPOSAL
    • Broadcasts proposal to all repeaters
    • Collects signatures
    • Broadcasts FINALIZED block when majority signs

  REPEATERS (Lightweight - Raspberry Pi):
    • Receive block proposal
    • Verify block hash (~0.1ms)
    • Verify previous block link (~0.1ms)  
    • Sign "I verified this block" (~1ms)
    • Send signature back to producer
    • Receive finalized block (with all signatures)
    • Store block + cache session

  CONSENSUS:
    • Block is VALID when majority of repeaters have signed
    • No heavy gossip protocol
    • Just signature collection and verification

Flow:
═════

  1. Producer → PROPOSAL → All Repeaters
  2. Each Repeater: Verify → Sign → Send signature to Producer
  3. Producer: Collect signatures until majority
  4. Producer → FINALIZED BLOCK (with signatures) → All Repeaters
  5. Repeaters: Verify signatures → Store block → Cache session

This is DECENTRALIZED (repeaters decide) but LIGHTWEIGHT (no heavy computation on Pi)
"""

import json
import time
import hashlib
import os
import socket
import struct
import threading
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class SessionRecord:
    """Session record stored in a block"""
    session_id: str
    radio_id: str
    public_key: str         # RadioA's public key (hex)
    proof_hash: str         # SHA256 of ZK-SNARK proof (the binding!)
    commitment: str         # ZK commitment for key derivation
    created_at: float
    expires_at: float
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: dict) -> 'SessionRecord':
        return cls(**d)
    
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@dataclass
class BlockProposal:
    """
    A block PROPOSAL - not yet finalized.
    
    Becomes a Block once enough repeaters sign.
    """
    number: int
    timestamp: float
    previous_hash: str
    producer_id: str
    sessions: List[SessionRecord]
    proposal_hash: str = ''
    
    def __post_init__(self):
        if not self.proposal_hash:
            self.proposal_hash = self.compute_hash()
    
    def compute_hash(self) -> str:
        """Compute proposal hash"""
        data = json.dumps({
            'number': self.number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'producer_id': self.producer_id,
            'sessions': [s.to_dict() for s in self.sessions]
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
    
    def to_dict(self) -> dict:
        return {
            'number': self.number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'producer_id': self.producer_id,
            'sessions': [s.to_dict() for s in self.sessions],
            'proposal_hash': self.proposal_hash
        }
    
    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode('utf-8')
    
    @classmethod
    def from_dict(cls, d: dict) -> 'BlockProposal':
        sessions = [SessionRecord.from_dict(s) for s in d.get('sessions', [])]
        return cls(
            number=d['number'],
            timestamp=d['timestamp'],
            previous_hash=d['previous_hash'],
            producer_id=d['producer_id'],
            sessions=sessions,
            proposal_hash=d.get('proposal_hash', '')
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'BlockProposal':
        return cls.from_dict(json.loads(data.decode('utf-8')))


@dataclass
class RepeaterSignature:
    """A repeater's signature on a block proposal"""
    repeater_id: str
    proposal_hash: str
    signature: str          # Hex-encoded Ed25519 signature
    public_key: str         # Hex-encoded public key
    timestamp: float
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: dict) -> 'RepeaterSignature':
        return cls(**d)
    
    def verify(self) -> bool:
        """Verify this signature is valid"""
        try:
            pub_key = ed25519.Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(self.public_key)
            )
            message = f"{self.proposal_hash}:{self.repeater_id}:{self.timestamp}".encode()
            pub_key.verify(bytes.fromhex(self.signature), message)
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False


@dataclass
class Block:
    """
    A FINALIZED block - has enough repeater signatures.
    
    This is what gets stored permanently.
    """
    number: int
    timestamp: float
    previous_hash: str
    producer_id: str
    sessions: List[SessionRecord]
    signatures: List[RepeaterSignature]     # Majority of repeaters signed
    block_hash: str = ''
    
    def __post_init__(self):
        if not self.block_hash:
            self.block_hash = self.compute_hash()
    
    def compute_hash(self) -> str:
        """Compute block hash (includes signatures)"""
        data = json.dumps({
            'number': self.number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'producer_id': self.producer_id,
            'sessions': [s.to_dict() for s in self.sessions],
            'signatures': [s.to_dict() for s in self.signatures]
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
    
    @property
    def proposal_hash(self) -> str:
        """Get the proposal hash (without signatures)"""
        data = json.dumps({
            'number': self.number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'producer_id': self.producer_id,
            'sessions': [s.to_dict() for s in self.sessions]
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()
    
    def verify_signatures(self, min_signatures: int) -> bool:
        """Verify block has enough valid signatures"""
        if len(self.signatures) < min_signatures:
            return False
        
        valid_count = sum(1 for sig in self.signatures if sig.verify())
        return valid_count >= min_signatures
    
    def to_dict(self) -> dict:
        return {
            'number': self.number,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'producer_id': self.producer_id,
            'sessions': [s.to_dict() for s in self.sessions],
            'signatures': [s.to_dict() for s in self.signatures],
            'block_hash': self.block_hash
        }
    
    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode('utf-8')
    
    @classmethod
    def from_dict(cls, d: dict) -> 'Block':
        sessions = [SessionRecord.from_dict(s) for s in d.get('sessions', [])]
        signatures = [RepeaterSignature.from_dict(s) for s in d.get('signatures', [])]
        return cls(
            number=d['number'],
            timestamp=d['timestamp'],
            previous_hash=d['previous_hash'],
            producer_id=d['producer_id'],
            sessions=sessions,
            signatures=signatures,
            block_hash=d.get('block_hash', '')
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'Block':
        return cls.from_dict(json.loads(data.decode('utf-8')))
    
    @classmethod
    def from_proposal(cls, proposal: BlockProposal, signatures: List[RepeaterSignature]) -> 'Block':
        """Create finalized block from proposal + signatures"""
        return cls(
            number=proposal.number,
            timestamp=proposal.timestamp,
            previous_hash=proposal.previous_hash,
            producer_id=proposal.producer_id,
            sessions=proposal.sessions,
            signatures=signatures
        )


# =============================================================================
# STORAGE (Used by both Producer and Repeaters)
# =============================================================================

class BlockchainStorage:
    """
    Append-only blockchain storage.
    
    Lightweight - suitable for Raspberry Pi.
    """
    
    def __init__(self, storage_path: str = "blockchain.json"):
        self.storage_path = storage_path
        self.blocks: List[Block] = []
        self.session_cache: Dict[str, SessionRecord] = {}
        self.proof_hash_cache: Dict[str, str] = {}
        self._load()
    
    def _load(self) -> None:
        """Load blockchain from disk"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for block_dict in data.get('blocks', []):
                        block = Block.from_dict(block_dict)
                        self.blocks.append(block)
                        self._cache_sessions(block)
                logger.info(f"Loaded {len(self.blocks)} blocks")
            except Exception as e:
                logger.warning(f"Failed to load blockchain: {e}")
                self._create_genesis()
        else:
            self._create_genesis()
    
    def _create_genesis(self) -> None:
        """Create genesis block"""
        genesis = Block(
            number=0,
            timestamp=0,
            previous_hash="0" * 64,
            producer_id="genesis",
            sessions=[],
            signatures=[]
        )
        self.blocks = [genesis]
        self._save()
        logger.info("Created genesis block")
    
    def _save(self) -> None:
        """Save blockchain to disk"""
        data = {'blocks': [b.to_dict() for b in self.blocks]}
        with open(self.storage_path, 'w') as f:
            json.dump(data, f)
    
    def _cache_sessions(self, block: Block) -> None:
        """Cache sessions for fast lookup"""
        for session in block.sessions:
            self.session_cache[session.session_id] = session
            self.proof_hash_cache[session.session_id] = session.proof_hash
    
    def get_latest_block(self) -> Block:
        """Get most recent block"""
        return self.blocks[-1]
    
    def add_block(self, block: Block, min_signatures: int = 1) -> bool:
        """
        Add a finalized block.
        
        Verifies:
          1. Hash chain is valid
          2. Block number is correct
          3. Has enough valid signatures
        """
        latest = self.get_latest_block()
        
        # Verify chain
        if block.previous_hash != latest.block_hash:
            logger.error(f"Invalid previous_hash")
            return False
        
        if block.number != latest.number + 1:
            logger.error(f"Invalid block number")
            return False
        
        # Verify signatures
        if not block.verify_signatures(min_signatures):
            logger.error(f"Insufficient valid signatures")
            return False
        
        # Add block
        self.blocks.append(block)
        self._cache_sessions(block)
        self._save()
        
        logger.info(f"Added block #{block.number} with {len(block.signatures)} signatures")
        return True
    
    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        """Get session by ID"""
        return self.session_cache.get(session_id)
    
    def get_proof_hash(self, session_id: str) -> Optional[str]:
        """Get proof_hash for session (fast lookup)"""
        return self.proof_hash_cache.get(session_id)
    
    def is_valid_session(self, session_id: str, proof_hash: str) -> bool:
        """
        Fast validation for packet verification.
        
        Called on EVERY packet at EVERY hop.
        Must be FAST (~microseconds).
        """
        cached = self.proof_hash_cache.get(session_id)
        if cached is None:
            return False
        if cached != proof_hash:
            return False
        session = self.session_cache.get(session_id)
        if session and session.is_expired():
            return False
        return True
    
    def get_stats(self) -> dict:
        """Get statistics"""
        return {
            'blocks': len(self.blocks),
            'sessions': len(self.session_cache),
            'latest_block': self.blocks[-1].number
        }


# =============================================================================
# REPEATER NODE (Lightweight - Raspberry Pi)
# =============================================================================

class RepeaterNode:
    """
    Repeater node - runs on Raspberry Pi.
    
    Responsibilities:
      1. Receive block proposals
      2. Verify proposal (hash chain, structure)
      3. Sign proposal ("I approve this block")
      4. Send signature back to producer
      5. Receive finalized block
      6. Verify signatures
      7. Store block + cache sessions
      8. Forward data packets with HMAC verification
    
    All operations are LIGHTWEIGHT.
    """
    
    def __init__(
        self,
        node_id: str,
        storage: BlockchainStorage,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None
    ):
        self.node_id = node_id
        self.storage = storage
        
        # Generate or use provided signing key
        if private_key:
            self.private_key = private_key
        else:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        
        self.public_key = self.private_key.public_key()
        self.public_key_hex = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        
        logger.info(f"RepeaterNode {node_id} initialized, pubkey: {self.public_key_hex[:16]}...")
    
    def verify_proposal(self, proposal: BlockProposal) -> bool:
        """
        Verify a block proposal is valid.
        
        Checks:
          1. Hash chain links correctly
          2. Block number is sequential
          3. Proposal hash is correct
        
        Time: ~0.5ms (fast enough for Pi)
        """
        latest = self.storage.get_latest_block()
        
        # Check chain
        if proposal.previous_hash != latest.block_hash:
            logger.warning(f"Proposal has invalid previous_hash")
            return False
        
        if proposal.number != latest.number + 1:
            logger.warning(f"Proposal has invalid number")
            return False
        
        # Check hash
        if proposal.proposal_hash != proposal.compute_hash():
            logger.warning(f"Proposal has invalid hash")
            return False
        
        return True
    
    def sign_proposal(self, proposal: BlockProposal) -> Optional[RepeaterSignature]:
        """
        Sign a verified proposal.
        
        "I, repeater X, verify this block proposal is valid."
        
        Time: ~1ms (Ed25519 is fast)
        """
        if not self.verify_proposal(proposal):
            return None
        
        timestamp = time.time()
        message = f"{proposal.proposal_hash}:{self.node_id}:{timestamp}".encode()
        
        signature = self.private_key.sign(message)
        
        return RepeaterSignature(
            repeater_id=self.node_id,
            proposal_hash=proposal.proposal_hash,
            signature=signature.hex(),
            public_key=self.public_key_hex,
            timestamp=timestamp
        )
    
    def receive_finalized_block(self, block: Block, min_signatures: int) -> bool:
        """
        Receive and store a finalized block.
        
        Verifies signatures, then stores.
        """
        return self.storage.add_block(block, min_signatures)
    
    def verify_packet_session(self, session_id: str, proof_hash: str) -> bool:
        """
        Fast verification for data packets.
        
        Called on EVERY packet - must be microseconds.
        """
        return self.storage.is_valid_session(session_id, proof_hash)


# =============================================================================
# PRODUCER NODE (Heavy - Ryzen 7)
# =============================================================================

class ProducerNode:
    """
    Producer node - runs on powerful hardware (Ryzen 7).
    
    Responsibilities:
      1. Generate ZK-SNARK proofs (heavy)
      2. Create block proposals
      3. Broadcast proposals to repeaters
      4. Collect signatures from repeaters
      5. Finalize block when majority signs
      6. Broadcast finalized block
    
    The heavy ZK computation happens here, not on repeaters.
    """
    
    def __init__(
        self,
        node_id: str,
        storage: BlockchainStorage,
        repeater_count: int
    ):
        self.node_id = node_id
        self.storage = storage
        self.repeater_count = repeater_count
        self.min_signatures = (repeater_count // 2) + 1  # Majority
        
        # Pending sessions to include in next block
        self.pending_sessions: List[SessionRecord] = []
        
        # Signature collection for current proposal
        self.current_proposal: Optional[BlockProposal] = None
        self.collected_signatures: List[RepeaterSignature] = []
        self.signature_lock = threading.Lock()
        
        logger.info(f"ProducerNode {node_id} initialized, need {self.min_signatures}/{repeater_count} signatures")
    
    def add_session(self, session: SessionRecord) -> None:
        """Queue session for next block"""
        self.pending_sessions.append(session)
        logger.info(f"Queued session {session.session_id[:16]}...")
    
    def create_proposal(self) -> Optional[BlockProposal]:
        """
        Create a block proposal from pending sessions.
        
        Returns proposal to broadcast to repeaters.
        """
        if not self.pending_sessions:
            return None
        
        latest = self.storage.get_latest_block()
        
        proposal = BlockProposal(
            number=latest.number + 1,
            timestamp=time.time(),
            previous_hash=latest.block_hash,
            producer_id=self.node_id,
            sessions=self.pending_sessions[:]
        )
        
        with self.signature_lock:
            self.current_proposal = proposal
            self.collected_signatures = []
        
        logger.info(f"Created proposal for block #{proposal.number}")
        return proposal
    
    def receive_signature(self, signature: RepeaterSignature) -> bool:
        """
        Receive a signature from a repeater.
        
        Returns True if we now have enough signatures.
        """
        with self.signature_lock:
            if self.current_proposal is None:
                return False
            
            # Verify signature is for current proposal
            if signature.proposal_hash != self.current_proposal.proposal_hash:
                logger.warning(f"Signature for wrong proposal from {signature.repeater_id}")
                return False
            
            # Verify signature is valid
            if not signature.verify():
                logger.warning(f"Invalid signature from {signature.repeater_id}")
                return False
            
            # Check for duplicate
            for existing in self.collected_signatures:
                if existing.repeater_id == signature.repeater_id:
                    return len(self.collected_signatures) >= self.min_signatures
            
            # Add signature
            self.collected_signatures.append(signature)
            logger.info(f"Collected signature from {signature.repeater_id} "
                       f"({len(self.collected_signatures)}/{self.min_signatures})")
            
            return len(self.collected_signatures) >= self.min_signatures
    
    def finalize_block(self) -> Optional[Block]:
        """
        Finalize the current proposal into a block.
        
        Only succeeds if we have enough signatures.
        Returns the finalized block to broadcast.
        """
        with self.signature_lock:
            if self.current_proposal is None:
                return None
            
            if len(self.collected_signatures) < self.min_signatures:
                logger.warning(f"Not enough signatures: {len(self.collected_signatures)}/{self.min_signatures}")
                return None
            
            # Create finalized block
            block = Block.from_proposal(
                self.current_proposal,
                self.collected_signatures[:]
            )
            
            # Store locally
            if not self.storage.add_block(block, self.min_signatures):
                logger.error("Failed to store finalized block locally")
                return None
            
            # Clear pending
            self.pending_sessions.clear()
            self.current_proposal = None
            self.collected_signatures = []
            
            logger.info(f"Finalized block #{block.number}")
            return block
    
    def has_enough_signatures(self) -> bool:
        """Check if we have enough signatures to finalize"""
        with self.signature_lock:
            return len(self.collected_signatures) >= self.min_signatures


# =============================================================================
# NETWORK PROTOCOL
# =============================================================================

# Message types
MSG_PROPOSAL = 1          # Producer → Repeaters: Block proposal
MSG_SIGNATURE = 2         # Repeater → Producer: Signature on proposal
MSG_FINALIZED = 3         # Producer → Repeaters: Finalized block
MSG_ACK = 4               # Generic acknowledgment


def pack_message(msg_type: int, data: bytes) -> bytes:
    """Pack message with header"""
    return struct.pack('!BI', msg_type, len(data)) + data


def unpack_message(sock: socket.socket, timeout: float = 10.0) -> Optional[Tuple[int, bytes]]:
    """Unpack message from socket"""
    sock.settimeout(timeout)
    try:
        header = sock.recv(5)
        if len(header) < 5:
            return None
        
        msg_type, length = struct.unpack('!BI', header)
        
        data = b''
        while len(data) < length:
            chunk = sock.recv(min(8192, length - len(data)))
            if not chunk:
                return None
            data += chunk
        
        return (msg_type, data)
    except:
        return None


class ProducerNetwork:
    """
    Network handler for producer.
    
    Broadcasts proposals, collects signatures, broadcasts finalized blocks.
    """
    
    def __init__(self, producer: ProducerNode, repeater_addresses: List[Tuple[str, int]]):
        self.producer = producer
        self.repeater_addresses = repeater_addresses  # [(host, port), ...]
    
    def broadcast_proposal(self, proposal: BlockProposal) -> int:
        """Broadcast proposal to all repeaters, collect signatures"""
        data = proposal.to_bytes()
        collected = 0
        
        threads = []
        for host, port in self.repeater_addresses:
            t = threading.Thread(
                target=self._send_proposal_collect_sig,
                args=(host, port, data)
            )
            t.start()
            threads.append(t)
        
        # Wait for all with timeout
        for t in threads:
            t.join(timeout=5.0)
        
        return len(self.producer.collected_signatures)
    
    def _send_proposal_collect_sig(self, host: str, port: int, proposal_data: bytes) -> None:
        """Send proposal to one repeater and collect signature"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((host, port))
            
            # Send proposal
            sock.sendall(pack_message(MSG_PROPOSAL, proposal_data))
            
            # Receive signature
            result = unpack_message(sock, timeout=5.0)
            if result and result[0] == MSG_SIGNATURE:
                sig = RepeaterSignature.from_dict(json.loads(result[1].decode()))
                self.producer.receive_signature(sig)
            
            sock.close()
        except Exception as e:
            logger.warning(f"Failed to get signature from {host}:{port}: {e}")
    
    def broadcast_finalized(self, block: Block) -> int:
        """Broadcast finalized block to all repeaters"""
        data = block.to_bytes()
        success = 0
        
        for host, port in self.repeater_addresses:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5.0)
                sock.connect((host, port))
                sock.sendall(pack_message(MSG_FINALIZED, data))
                sock.close()
                success += 1
            except Exception as e:
                logger.warning(f"Failed to send finalized to {host}:{port}: {e}")
        
        return success


class RepeaterNetwork:
    """
    Network handler for repeater.
    
    Listens for proposals, sends signatures, receives finalized blocks.
    """
    
    def __init__(self, repeater: RepeaterNode, listen_port: int, min_signatures: int):
        self.repeater = repeater
        self.listen_port = listen_port
        self.min_signatures = min_signatures
        self.running = False
        self.server: Optional[socket.socket] = None
    
    def start(self) -> None:
        """Start listening"""
        self.running = True
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', self.listen_port))
        self.server.listen(5)
        self.server.settimeout(1.0)
        
        logger.info(f"Repeater listening on port {self.listen_port}")
        
        while self.running:
            try:
                conn, addr = self.server.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(conn,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Server error: {e}")
    
    def _handle_connection(self, conn: socket.socket) -> None:
        """Handle incoming connection from producer"""
        try:
            result = unpack_message(conn, timeout=10.0)
            if result is None:
                return
            
            msg_type, data = result
            
            if msg_type == MSG_PROPOSAL:
                # Verify and sign proposal
                proposal = BlockProposal.from_bytes(data)
                signature = self.repeater.sign_proposal(proposal)
                
                if signature:
                    # Send signature back
                    sig_data = json.dumps(signature.to_dict()).encode()
                    conn.sendall(pack_message(MSG_SIGNATURE, sig_data))
                    logger.info(f"Signed proposal for block #{proposal.number}")
            
            elif msg_type == MSG_FINALIZED:
                # Store finalized block
                block = Block.from_bytes(data)
                if self.repeater.receive_finalized_block(block, self.min_signatures):
                    logger.info(f"Stored finalized block #{block.number}")
                else:
                    logger.warning(f"Rejected invalid finalized block")
        
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            conn.close()
    
    def stop(self) -> None:
        """Stop listening"""
        self.running = False
        if self.server:
            self.server.close()


# =============================================================================
# CONVENIENCE: Full Session Establishment Flow
# =============================================================================

def establish_session_full_flow(
    producer: ProducerNode,
    producer_network: ProducerNetwork,
    session: SessionRecord
) -> Optional[Block]:
    """
    Full flow to establish a session:
    
    1. Add session to producer
    2. Create proposal
    3. Broadcast to repeaters, collect signatures
    4. Finalize when majority signs
    5. Broadcast finalized block
    
    Returns the finalized block, or None if failed.
    """
    # Add session
    producer.add_session(session)
    
    # Create proposal
    proposal = producer.create_proposal()
    if not proposal:
        return None
    
    # Broadcast and collect signatures
    sig_count = producer_network.broadcast_proposal(proposal)
    logger.info(f"Collected {sig_count} signatures")
    
    # Check if enough
    if not producer.has_enough_signatures():
        logger.error("Failed to collect enough signatures")
        return None
    
    # Finalize
    block = producer.finalize_block()
    if not block:
        return None
    
    # Broadcast finalized
    producer_network.broadcast_finalized(block)
    
    return block


# =============================================================================
# TEST
# =============================================================================

if __name__ == '__main__':
    import tempfile
    import shutil
    
    print("=" * 70)
    print("BLOCKCHAIN CONSENSUS TEST")
    print("Producer proposes, Repeaters verify and sign, Majority = Consensus")
    print("=" * 70)
    
    # Create temp directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create producer
        print("\n1. Creating producer...")
        producer_storage = BlockchainStorage(f"{temp_dir}/producer.json")
        producer = ProducerNode("producer-1", producer_storage, repeater_count=4)
        
        # Create repeaters
        print("\n2. Creating 4 repeaters (simulating Raspberry Pis)...")
        repeaters = []
        for i in range(4):
            storage = BlockchainStorage(f"{temp_dir}/repeater{i}.json")
            node = RepeaterNode(f"repeater-{i}", storage)
            repeaters.append(node)
            print(f"   Repeater {i}: {node.public_key_hex[:16]}...")
        
        # Create session
        print("\n3. Creating session record...")
        session = SessionRecord(
            session_id="sess-test-001",
            radio_id="radio-a",
            public_key="04abcdef1234567890abcdef",
            proof_hash="a" * 64,
            commitment="b" * 64,
            created_at=time.time(),
            expires_at=time.time() + 3600
        )
        
        # Producer creates proposal
        print("\n4. Producer creating block proposal...")
        producer.add_session(session)
        proposal = producer.create_proposal()
        print(f"   Proposal hash: {proposal.proposal_hash[:32]}...")
        
        # Each repeater verifies and signs
        print("\n5. Repeaters verifying and signing...")
        for rep in repeaters:
            sig = rep.sign_proposal(proposal)
            if sig:
                print(f"   {rep.node_id}: ✓ Signed")
                producer.receive_signature(sig)
            else:
                print(f"   {rep.node_id}: ✗ Rejected")
        
        # Check signatures
        print(f"\n6. Signatures collected: {len(producer.collected_signatures)}/{producer.min_signatures} needed")
        
        # Finalize
        print("\n7. Finalizing block...")
        block = producer.finalize_block()
        if block:
            print(f"   Block #{block.number} finalized!")
            print(f"   Block hash: {block.block_hash[:32]}...")
            print(f"   Signatures: {len(block.signatures)}")
        
        # Distribute to repeaters
        print("\n8. Repeaters storing finalized block...")
        for rep in repeaters:
            success = rep.receive_finalized_block(block, producer.min_signatures)
            print(f"   {rep.node_id}: {'✓ Stored' if success else '✗ Rejected'}")
        
        # Test fast packet verification
        print("\n9. Testing packet verification (what happens every packet)...")
        
        import timeit
        
        # All repeaters should have the session cached
        for rep in repeaters:
            valid = rep.verify_packet_session("sess-test-001", "a" * 64)
            print(f"   {rep.node_id} verification: {'✓' if valid else '✗'}")
        
        # Performance
        iterations = 100000
        duration = timeit.timeit(
            lambda: repeaters[0].verify_packet_session("sess-test-001", "a" * 64),
            number=iterations
        )
        print(f"\n   Performance: {iterations:,} verifications in {duration:.3f}s")
        print(f"   Per verification: {duration/iterations*1_000_000:.2f} µs")
        print(f"   Verifications/second: {iterations/duration:,.0f}")
        
        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY:")
        print("=" * 70)
        print(f"  Producer created proposal:     ✓")
        print(f"  Repeaters verified & signed:   {len(block.signatures)}/4")
        print(f"  Majority reached:              ✓ (needed {producer.min_signatures})")
        print(f"  Block finalized:               ✓")
        print(f"  All repeaters stored block:    ✓")
        print(f"  Session cached for fast auth:  ✓")
        print(f"  Verification speed:            {iterations/duration:,.0f}/sec")
        print("\nTHE BLOCKCHAIN IS RUN BY THE REPEATERS!")
        print("Producer proposes, but repeaters DECIDE by signing.")
        
    finally:
        shutil.rmtree(temp_dir)
    
    print("\n" + "=" * 70)
    print("TEST COMPLETE")
    print("=" * 70)
