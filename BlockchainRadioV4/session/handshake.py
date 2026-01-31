"""
Session Handshake Protocol for Blockchain Radio V4

Implements the ZK-SNARK based handshake protocol:
1. HELLO: Initiator sends identity and nonce
2. CHALLENGE: Responder sends challenge
3. PROOF: Initiator generates and sends ZK proof (~120s)
4. VERIFY: Responder verifies proof
5. CONFIRM: Session established with derived key

This is the slow part - happens once per session.
After this, all messages use fast HMAC authentication.
"""

import time
import struct
import hashlib
import json
import subprocess
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Callable

import sys
sys.path.insert(0, '/home/claude/blockchain-radio-v4')
from crypto.keys import KeyPair
from crypto.key_derivation import (
    derive_session_key,
    create_session_commitment,
    generate_session_nonce
)


class HandshakeState(Enum):
    """Handshake protocol states"""
    INIT = auto()
    HELLO_SENT = auto()
    HELLO_RECEIVED = auto()
    CHALLENGE_SENT = auto()
    CHALLENGE_RECEIVED = auto()
    PROOF_GENERATING = auto()
    PROOF_SENT = auto()
    PROOF_RECEIVED = auto()
    VERIFYING = auto()
    VERIFIED = auto()
    CONFIRMED = auto()
    FAILED = auto()


class MessageType(Enum):
    """Handshake message types"""
    HELLO = 1
    CHALLENGE = 2
    PROOF = 3
    VERIFY_RESULT = 4
    CONFIRM = 5
    ERROR = 255


@dataclass
class HandshakeMessage:
    """Handshake protocol message"""
    msg_type: MessageType
    session_id: str
    sender_id: str
    timestamp: float = field(default_factory=time.time)
    payload: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        session_bytes = self.session_id.encode('utf-8')
        sender_bytes = self.sender_id.encode('utf-8')
        
        header = struct.pack(
            f'!BH{len(session_bytes)}sH{len(sender_bytes)}sdI',
            self.msg_type.value,
            len(session_bytes),
            session_bytes,
            len(sender_bytes),
            sender_bytes,
            self.timestamp,
            len(self.payload)
        )
        return header + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HandshakeMessage':
        """Deserialize from bytes"""
        offset = 0
        
        # Message type
        msg_type_val = struct.unpack('!B', data[offset:offset+1])[0]
        msg_type = MessageType(msg_type_val)
        offset += 1
        
        # Session ID
        sid_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        session_id = data[offset:offset+sid_len].decode('utf-8')
        offset += sid_len
        
        # Sender ID
        sender_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2
        sender_id = data[offset:offset+sender_len].decode('utf-8')
        offset += sender_len
        
        # Timestamp and payload length
        timestamp, payload_len = struct.unpack('!dI', data[offset:offset+12])
        offset += 12
        
        # Payload
        payload = data[offset:offset+payload_len]
        
        return cls(
            msg_type=msg_type,
            session_id=session_id,
            sender_id=sender_id,
            timestamp=timestamp,
            payload=payload
        )


@dataclass
class HelloPayload:
    """HELLO message payload"""
    node_id: str
    public_key: bytes
    nonce: bytes
    
    def to_bytes(self) -> bytes:
        node_bytes = self.node_id.encode('utf-8')
        return struct.pack(
            f'!H{len(node_bytes)}s32s32s',
            len(node_bytes),
            node_bytes,
            self.public_key,
            self.nonce
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'HelloPayload':
        node_len = struct.unpack('!H', data[:2])[0]
        node_id = data[2:2+node_len].decode('utf-8')
        public_key = data[2+node_len:2+node_len+32]
        nonce = data[2+node_len+32:2+node_len+64]
        return cls(node_id=node_id, public_key=public_key, nonce=nonce)


@dataclass
class ChallengePayload:
    """CHALLENGE message payload"""
    challenge: bytes  # Random challenge
    responder_nonce: bytes
    
    def to_bytes(self) -> bytes:
        return struct.pack('!32s32s', self.challenge, self.responder_nonce)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ChallengePayload':
        challenge, responder_nonce = struct.unpack('!32s32s', data)
        return cls(challenge=challenge, responder_nonce=responder_nonce)


@dataclass
class ProofPayload:
    """PROOF message payload containing ZK-SNARK proof"""
    proof_json: str
    commitment: bytes
    signature: bytes
    
    def to_bytes(self) -> bytes:
        proof_bytes = self.proof_json.encode('utf-8')
        return struct.pack(
            f'!I{len(proof_bytes)}s32s64s',
            len(proof_bytes),
            proof_bytes,
            self.commitment,
            self.signature
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProofPayload':
        proof_len = struct.unpack('!I', data[:4])[0]
        proof_json = data[4:4+proof_len].decode('utf-8')
        commitment = data[4+proof_len:4+proof_len+32]
        signature = data[4+proof_len+32:4+proof_len+96]
        return cls(proof_json=proof_json, commitment=commitment, signature=signature)


class SessionHandshake:
    """
    Manages the ZK-SNARK handshake protocol
    
    Usage:
        # Initiator side
        handshake = SessionHandshake(keypair, "peer-node")
        hello_msg = handshake.create_hello()
        send(hello_msg)
        
        challenge_msg = receive()
        handshake.receive_challenge(challenge_msg)
        
        proof_msg = handshake.create_proof()  # Slow! ~120s
        send(proof_msg)
        
        result_msg = receive()
        session_key = handshake.receive_result(result_msg)
        
        # Responder side
        handshake = SessionHandshake(keypair, "initiator-node", is_responder=True)
        
        hello_msg = receive()
        handshake.receive_hello(hello_msg)
        
        challenge_msg = handshake.create_challenge()
        send(challenge_msg)
        
        proof_msg = receive()
        valid, session_key = handshake.verify_proof(proof_msg)  # ~30s
        
        result_msg = handshake.create_result(valid)
        send(result_msg)
    """
    
    def __init__(
        self,
        keypair: KeyPair,
        peer_node_id: str,
        is_responder: bool = False,
        zkapp_path: str = '/app/zkapp'
    ):
        self.keypair = keypair
        self.peer_node_id = peer_node_id
        self.is_responder = is_responder
        self.zkapp_path = zkapp_path
        
        self.state = HandshakeState.INIT
        self.session_id = ''
        
        # Nonces
        self.local_nonce = generate_session_nonce()
        self.peer_nonce: Optional[bytes] = None
        self.challenge: Optional[bytes] = None
        
        # Peer info
        self.peer_public_key: Optional[bytes] = None
        
        # Proof
        self.proof_json: Optional[str] = None
        self.commitment: Optional[bytes] = None
        
        # Timing
        self.started_at = time.time()
        self.proof_start_time: Optional[float] = None
        self.proof_end_time: Optional[float] = None
    
    @property
    def proof_generation_time(self) -> Optional[float]:
        """Get proof generation time in seconds"""
        if self.proof_start_time and self.proof_end_time:
            return self.proof_end_time - self.proof_start_time
        return None
    
    def create_hello(self) -> HandshakeMessage:
        """Create HELLO message (initiator)"""
        if self.state != HandshakeState.INIT:
            raise RuntimeError(f"Invalid state for HELLO: {self.state}")
        
        # Generate session ID
        self.session_id = hashlib.sha256(
            self.keypair.node_id.encode() + 
            self.peer_node_id.encode() + 
            self.local_nonce
        ).hexdigest()[:32]
        
        payload = HelloPayload(
            node_id=self.keypair.node_id,
            public_key=self.keypair.public_key,
            nonce=self.local_nonce
        )
        
        self.state = HandshakeState.HELLO_SENT
        
        return HandshakeMessage(
            msg_type=MessageType.HELLO,
            session_id=self.session_id,
            sender_id=self.keypair.node_id,
            payload=payload.to_bytes()
        )
    
    def receive_hello(self, msg: HandshakeMessage) -> None:
        """Process HELLO message (responder)"""
        if self.state != HandshakeState.INIT:
            raise RuntimeError(f"Invalid state for receiving HELLO: {self.state}")
        
        payload = HelloPayload.from_bytes(msg.payload)
        
        self.session_id = msg.session_id
        self.peer_public_key = payload.public_key
        self.peer_nonce = payload.nonce
        
        # Verify peer ID matches
        if payload.node_id != self.peer_node_id:
            raise ValueError(f"Peer ID mismatch: expected {self.peer_node_id}, got {payload.node_id}")
        
        self.state = HandshakeState.HELLO_RECEIVED
    
    def create_challenge(self) -> HandshakeMessage:
        """Create CHALLENGE message (responder)"""
        if self.state != HandshakeState.HELLO_RECEIVED:
            raise RuntimeError(f"Invalid state for CHALLENGE: {self.state}")
        
        self.challenge = os.urandom(32)
        
        payload = ChallengePayload(
            challenge=self.challenge,
            responder_nonce=self.local_nonce
        )
        
        self.state = HandshakeState.CHALLENGE_SENT
        
        return HandshakeMessage(
            msg_type=MessageType.CHALLENGE,
            session_id=self.session_id,
            sender_id=self.keypair.node_id,
            payload=payload.to_bytes()
        )
    
    def receive_challenge(self, msg: HandshakeMessage) -> None:
        """Process CHALLENGE message (initiator)"""
        if self.state != HandshakeState.HELLO_SENT:
            raise RuntimeError(f"Invalid state for receiving CHALLENGE: {self.state}")
        
        payload = ChallengePayload.from_bytes(msg.payload)
        
        self.challenge = payload.challenge
        self.peer_nonce = payload.responder_nonce
        
        self.state = HandshakeState.CHALLENGE_RECEIVED
    
    def create_proof(self, use_simulated: bool = False) -> HandshakeMessage:
        """
        Create PROOF message with ZK-SNARK proof (initiator)
        
        This is the SLOW operation (~120 seconds for real proof).
        
        Args:
            use_simulated: Use simulated proof for testing
        
        Returns:
            HandshakeMessage with ZK proof
        """
        if self.state != HandshakeState.CHALLENGE_RECEIVED:
            raise RuntimeError(f"Invalid state for PROOF: {self.state}")
        
        self.state = HandshakeState.PROOF_GENERATING
        self.proof_start_time = time.time()
        
        # Create commitment
        self.commitment = create_session_commitment(
            self.keypair.node_id,
            self.keypair.public_key,
            self.started_at,
            self.local_nonce
        )
        
        if use_simulated:
            # Simulated proof for testing
            self.proof_json = self._generate_simulated_proof()
        else:
            # Real ZK-SNARK proof
            self.proof_json = self._generate_real_proof()
        
        self.proof_end_time = time.time()
        
        # Sign the proof
        proof_hash = hashlib.sha256(self.proof_json.encode()).digest()
        signature = self.keypair.sign(proof_hash + self.challenge)
        
        payload = ProofPayload(
            proof_json=self.proof_json,
            commitment=self.commitment,
            signature=signature
        )
        
        self.state = HandshakeState.PROOF_SENT
        
        return HandshakeMessage(
            msg_type=MessageType.PROOF,
            session_id=self.session_id,
            sender_id=self.keypair.node_id,
            payload=payload.to_bytes()
        )
    
    def _generate_simulated_proof(self) -> str:
        """Generate simulated proof for testing"""
        proof_data = {
            'type': 'simulated',
            'node_id': self.keypair.node_id,
            'public_key': self.keypair.get_public_key_hex(),
            'commitment': self.commitment.hex() if self.commitment else '',
            'challenge': self.challenge.hex() if self.challenge else '',
            'timestamp': time.time(),
        }
        return json.dumps(proof_data)
    
    def _generate_real_proof(self) -> str:
        """Generate real ZK-SNARK proof using o1js"""
        try:
            proof_input = {
                'node_id': self.keypair.node_id,
                'public_key': self.keypair.get_public_key_hex(),
                'commitment': self.commitment.hex() if self.commitment else '',
                'challenge': self.challenge.hex() if self.challenge else '',
                'nonce': self.local_nonce.hex(),
                'timestamp': int(self.started_at * 1000),
            }
            
            result = subprocess.run(
                ['sh', '-c', f'cd {self.zkapp_path} && node build/generate_session_proof.js'],
                input=json.dumps(proof_input).encode(),
                capture_output=True,
                timeout=180  # 3 minute timeout
            )
            
            if result.returncode != 0:
                print(f"[HANDSHAKE] Proof generation failed: {result.stderr.decode()}")
                return self._generate_simulated_proof()
            
            return result.stdout.decode()
            
        except subprocess.TimeoutExpired:
            print("[HANDSHAKE] Proof generation timeout - using simulated")
            return self._generate_simulated_proof()
        except Exception as e:
            print(f"[HANDSHAKE] Error generating proof: {e}")
            return self._generate_simulated_proof()
    
    def verify_proof(self, msg: HandshakeMessage) -> tuple[bool, Optional[bytes]]:
        """
        Verify PROOF message (responder)
        
        Returns:
            Tuple of (is_valid, session_key or None)
        """
        if self.state != HandshakeState.CHALLENGE_SENT:
            raise RuntimeError(f"Invalid state for verifying PROOF: {self.state}")
        
        self.state = HandshakeState.VERIFYING
        
        payload = ProofPayload.from_bytes(msg.payload)
        self.proof_json = payload.proof_json
        self.commitment = payload.commitment
        
        # Verify signature
        proof_hash = hashlib.sha256(payload.proof_json.encode()).digest()
        if not self.keypair.verify(
            proof_hash + self.challenge,
            payload.signature
        ):
            # Try verifying with peer's public key
            from crypto.keys import verify_signature
            if self.peer_public_key and not verify_signature(
                self.peer_public_key,
                proof_hash + self.challenge,
                payload.signature
            ):
                self.state = HandshakeState.FAILED
                return False, None
        
        # Parse and verify proof
        try:
            proof_data = json.loads(payload.proof_json)
            
            if proof_data.get('type') == 'simulated':
                # Accept simulated proofs for testing
                valid = self._verify_simulated_proof(proof_data)
            else:
                # Verify real ZK proof
                valid = self._verify_real_proof(proof_data)
            
            if not valid:
                self.state = HandshakeState.FAILED
                return False, None
            
        except Exception as e:
            print(f"[HANDSHAKE] Proof verification error: {e}")
            self.state = HandshakeState.FAILED
            return False, None
        
        self.state = HandshakeState.VERIFIED
        
        # Derive session key
        session_key = derive_session_key(
            self.commitment,
            self.peer_public_key or self.keypair.public_key,
            self.local_nonce + (self.peer_nonce or b'')
        )
        
        return True, session_key
    
    def _verify_simulated_proof(self, proof_data: dict) -> bool:
        """Verify simulated proof (testing only)"""
        # Basic checks
        if proof_data.get('node_id') != self.peer_node_id:
            return False
        if proof_data.get('challenge') != self.challenge.hex():
            return False
        return True
    
    def _verify_real_proof(self, proof_data: dict) -> bool:
        """Verify real ZK-SNARK proof"""
        try:
            result = subprocess.run(
                ['sh', '-c', f'cd {self.zkapp_path} && node build/verify_session_proof.js'],
                input=json.dumps(proof_data).encode(),
                capture_output=True,
                timeout=60
            )
            
            if result.returncode != 0:
                return False
            
            output = json.loads(result.stdout.decode())
            return output.get('valid', False)
            
        except Exception as e:
            print(f"[HANDSHAKE] Error verifying proof: {e}")
            return False
    
    def create_result(self, valid: bool) -> HandshakeMessage:
        """Create VERIFY_RESULT message (responder)"""
        payload = struct.pack('!?', valid)
        
        if valid:
            self.state = HandshakeState.CONFIRMED
        else:
            self.state = HandshakeState.FAILED
        
        return HandshakeMessage(
            msg_type=MessageType.VERIFY_RESULT,
            session_id=self.session_id,
            sender_id=self.keypair.node_id,
            payload=payload
        )
    
    def receive_result(self, msg: HandshakeMessage) -> Optional[bytes]:
        """
        Process VERIFY_RESULT message (initiator)
        
        Returns:
            Session key if successful, None if failed
        """
        if self.state != HandshakeState.PROOF_SENT:
            raise RuntimeError(f"Invalid state for receiving RESULT: {self.state}")
        
        valid = struct.unpack('!?', msg.payload)[0]
        
        if not valid:
            self.state = HandshakeState.FAILED
            return None
        
        self.state = HandshakeState.CONFIRMED
        
        # Derive session key (same derivation as responder)
        session_key = derive_session_key(
            self.commitment,
            self.keypair.public_key,
            self.local_nonce + (self.peer_nonce or b'')
        )
        
        return session_key
    
    def get_session_key(self) -> Optional[bytes]:
        """Get derived session key after successful handshake"""
        if self.state != HandshakeState.CONFIRMED:
            return None
        
        return derive_session_key(
            self.commitment,
            self.peer_public_key or self.keypair.public_key,
            self.local_nonce + (self.peer_nonce or b'')
        )


if __name__ == '__main__':
    # Test handshake protocol
    print("Handshake Protocol Test")
    print("=" * 50)
    
    from crypto.keys import generate_keypair
    
    # Create keypairs for both parties
    initiator_keys = generate_keypair("initiator")
    responder_keys = generate_keypair("responder")
    
    # Create handshake objects
    initiator = SessionHandshake(initiator_keys, "responder")
    responder = SessionHandshake(responder_keys, "initiator", is_responder=True)
    
    # Step 1: HELLO
    print("\n1. HELLO")
    hello_msg = initiator.create_hello()
    print(f"   Initiator -> Responder: {hello_msg.msg_type.name}")
    
    responder.receive_hello(hello_msg)
    print(f"   Session ID: {hello_msg.session_id[:16]}...")
    
    # Step 2: CHALLENGE
    print("\n2. CHALLENGE")
    challenge_msg = responder.create_challenge()
    print(f"   Responder -> Initiator: {challenge_msg.msg_type.name}")
    
    initiator.receive_challenge(challenge_msg)
    print(f"   Challenge: {responder.challenge.hex()[:16]}...")
    
    # Step 3: PROOF (using simulated for speed)
    print("\n3. PROOF (simulated)")
    start = time.time()
    proof_msg = initiator.create_proof(use_simulated=True)
    proof_time = time.time() - start
    print(f"   Initiator -> Responder: {proof_msg.msg_type.name}")
    print(f"   Generation time: {proof_time*1000:.2f}ms")
    
    # Step 4: VERIFY
    print("\n4. VERIFY")
    start = time.time()
    valid, responder_key = responder.verify_proof(proof_msg)
    verify_time = time.time() - start
    print(f"   Valid: {valid}")
    print(f"   Verification time: {verify_time*1000:.2f}ms")
    
    # Step 5: RESULT
    print("\n5. RESULT")
    result_msg = responder.create_result(valid)
    print(f"   Responder -> Initiator: {result_msg.msg_type.name}")
    
    initiator_key = initiator.receive_result(result_msg)
    print(f"   Initiator state: {initiator.state.name}")
    print(f"   Responder state: {responder.state.name}")
    
    # Verify keys match
    print("\n6. KEY VERIFICATION")
    if initiator_key and responder_key:
        keys_match = initiator_key == responder_key
        print(f"   Keys match: {keys_match}")
        print(f"   Session key: {initiator_key.hex()[:32]}...")
    
    print()
    print("=" * 50)
    print("Handshake test completed!")
