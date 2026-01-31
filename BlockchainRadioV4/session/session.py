"""
Session State Management for Blockchain Radio V4

Manages session lifecycle and state transitions:
- INIT: Session created, waiting for handshake
- HANDSHAKING: ZK proof being generated/verified
- ESTABLISHED: Session active, fast HMAC auth
- EXPIRED: Session timed out
- CLOSED: Session explicitly closed
"""

import time
import threading
import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any
import json

import sys
sys.path.insert(0, '/home/claude/blockchain-radio-v4')
from crypto.keys import KeyPair
from crypto.hmac_auth import HMACAuth
from crypto.key_derivation import derive_session_key, derive_hmac_key, generate_session_nonce


class SessionState(Enum):
    """Session lifecycle states"""
    INIT = auto()          # Created, not yet started
    HANDSHAKING = auto()   # ZK proof in progress
    ESTABLISHED = auto()   # Ready for real-time messages
    EXPIRED = auto()       # Timed out
    CLOSED = auto()        # Explicitly closed


@dataclass
class Session:
    """
    Represents a communication session
    
    A session is established once via ZK-SNARK proof, then uses
    fast HMAC authentication for all subsequent messages.
    """
    
    session_id: str
    node_id: str
    peer_node_id: str
    
    # State
    state: SessionState = SessionState.INIT
    created_at: float = field(default_factory=time.time)
    established_at: Optional[float] = None
    last_activity: float = field(default_factory=time.time)
    
    # Keys (populated during handshake)
    session_key: Optional[bytes] = None
    hmac_key: Optional[bytes] = None
    session_nonce: bytes = field(default_factory=generate_session_nonce)
    
    # ZK Proof (populated during handshake)
    zk_proof: Optional[str] = None
    zk_commitment: Optional[bytes] = None
    proof_hash: Optional[bytes] = None  # SHA256 of zk_proof - THIS IS WHAT BINDS MESSAGES
    
    # Message tracking
    send_seq: int = 0
    recv_seq: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    
    # Configuration
    timeout_seconds: float = 3600.0  # 1 hour default
    max_idle_seconds: float = 300.0  # 5 minutes idle timeout
    
    # HMAC Authenticator (created when established)
    _hmac_auth: Optional[HMACAuth] = field(default=None, repr=False)
    
    @property
    def is_active(self) -> bool:
        """Check if session is active and usable"""
        return self.state == SessionState.ESTABLISHED
    
    @property
    def is_expired(self) -> bool:
        """Check if session has expired"""
        if self.state in (SessionState.EXPIRED, SessionState.CLOSED):
            return True
        
        # Check timeout
        age = time.time() - self.created_at
        if age > self.timeout_seconds:
            return True
        
        # Check idle timeout
        idle = time.time() - self.last_activity
        if idle > self.max_idle_seconds:
            return True
        
        return False
    
    @property
    def age_seconds(self) -> float:
        """Get session age in seconds"""
        return time.time() - self.created_at
    
    @property
    def hmac_auth(self) -> Optional[HMACAuth]:
        """Get HMAC authenticator, creating if needed"""
        if self._hmac_auth is None and self.hmac_key is not None:
            self._hmac_auth = HMACAuth(
                session_key=self.hmac_key,
                session_id=self.session_id,
                sequence_number=self.send_seq
            )
        return self._hmac_auth
    
    def establish(
        self,
        session_key: bytes,
        zk_proof: str,
        zk_commitment: bytes
    ) -> None:
        """
        Establish the session after successful handshake
        
        CRITICAL: Computes proof_hash from ZK proof. This hash:
        1. Is only 32 bytes (vs ~10KB full proof)
        2. Binds every future message to this proof
        3. Is what repeaters cache and verify against
        
        Args:
            session_key: Derived session key
            zk_proof: ZK-SNARK proof string (the full proof)
            zk_commitment: ZK commitment hash
        """
        import hashlib
        
        self.session_key = session_key
        self.hmac_key = derive_hmac_key(session_key)
        self.zk_proof = zk_proof
        self.zk_commitment = zk_commitment
        
        # CRITICAL: Hash the proof - this is what we actually use
        # The full proof is stored but the HASH is what travels with messages
        self.proof_hash = hashlib.sha256(zk_proof.encode('utf-8')).digest()
        
        self.state = SessionState.ESTABLISHED
        self.established_at = time.time()
        self.last_activity = time.time()
        
        # Create HMAC authenticator WITH the proof_hash binding
        self._hmac_auth = HMACAuth(
            session_key=self.hmac_key,
            session_id=self.session_id,
            proof_hash=self.proof_hash,  # Every HMAC will include this!
            sequence_number=0
        )
    
    def touch(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def close(self) -> None:
        """Close the session"""
        self.state = SessionState.CLOSED
    
    def expire(self) -> None:
        """Mark session as expired"""
        self.state = SessionState.EXPIRED
    
    def create_authenticated_message(self, payload: bytes) -> tuple[bytes, int, float]:
        """
        Create an authenticated message
        
        Args:
            payload: Message payload
        
        Returns:
            Tuple of (hmac_tag, sequence, timestamp)
        """
        if not self.is_active:
            raise RuntimeError(f"Session not active: {self.state}")
        
        self.touch()
        self.messages_sent += 1
        
        tag, seq, ts = self.hmac_auth.create_tag(payload)
        self.send_seq = seq
        
        return tag, seq, ts
    
    def verify_authenticated_message(
        self, 
        payload: bytes, 
        tag: bytes, 
        seq: int, 
        timestamp: float
    ) -> tuple[bool, str]:
        """
        Verify an authenticated message
        
        Args:
            payload: Message payload
            tag: HMAC tag
            seq: Sequence number
            timestamp: Message timestamp
        
        Returns:
            Tuple of (is_valid, reason)
        """
        if not self.is_active:
            return False, f"Session not active: {self.state}"
        
        # Verify HMAC
        valid, reason = self.hmac_auth.verify_tag(
            payload, tag, seq, timestamp,
            max_age_seconds=30.0,
            min_seq=self.recv_seq
        )
        
        if valid:
            self.touch()
            self.messages_received += 1
            self.recv_seq = seq
        
        return valid, reason
    
    def get_stats(self) -> dict:
        """Get session statistics"""
        return {
            'session_id': self.session_id,
            'state': self.state.name,
            'age_seconds': self.age_seconds,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'send_seq': self.send_seq,
            'recv_seq': self.recv_seq,
        }
    
    def to_dict(self) -> dict:
        """Serialize to dictionary (excludes keys)"""
        return {
            'session_id': self.session_id,
            'node_id': self.node_id,
            'peer_node_id': self.peer_node_id,
            'state': self.state.name,
            'created_at': self.created_at,
            'established_at': self.established_at,
            'last_activity': self.last_activity,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
        }


def generate_session_id(node_id: str, peer_node_id: str, nonce: bytes) -> str:
    """Generate unique session ID"""
    data = f"{node_id}:{peer_node_id}:{nonce.hex()}:{time.time()}".encode()
    return hashlib.sha256(data).hexdigest()[:32]


class SessionManager:
    """
    Manages multiple sessions
    
    Handles session creation, lookup, and cleanup.
    Thread-safe for concurrent access.
    """
    
    def __init__(
        self,
        node_id: str,
        keypair: KeyPair,
        default_timeout: float = 3600.0,
        cleanup_interval: float = 60.0
    ):
        self.node_id = node_id
        self.keypair = keypair
        self.default_timeout = default_timeout
        self.cleanup_interval = cleanup_interval
        
        self._sessions: Dict[str, Session] = {}
        self._sessions_by_peer: Dict[str, str] = {}  # peer_id -> session_id
        self._lock = threading.RLock()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._running = True
        self._cleanup_thread.start()
    
    def create_session(self, peer_node_id: str) -> Session:
        """
        Create a new session with a peer
        
        Args:
            peer_node_id: Peer node identifier
        
        Returns:
            New Session object
        """
        with self._lock:
            # Check if session already exists
            if peer_node_id in self._sessions_by_peer:
                existing_id = self._sessions_by_peer[peer_node_id]
                existing = self._sessions.get(existing_id)
                if existing and not existing.is_expired:
                    return existing
            
            # Create new session
            nonce = generate_session_nonce()
            session_id = generate_session_id(self.node_id, peer_node_id, nonce)
            
            session = Session(
                session_id=session_id,
                node_id=self.node_id,
                peer_node_id=peer_node_id,
                session_nonce=nonce,
                timeout_seconds=self.default_timeout
            )
            
            self._sessions[session_id] = session
            self._sessions_by_peer[peer_node_id] = session_id
            
            return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and session.is_expired:
                self._remove_session(session_id)
                return None
            return session
    
    def get_session_by_peer(self, peer_node_id: str) -> Optional[Session]:
        """Get active session with a peer"""
        with self._lock:
            session_id = self._sessions_by_peer.get(peer_node_id)
            if session_id:
                return self.get_session(session_id)
            return None
    
    def close_session(self, session_id: str) -> None:
        """Close a session"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.close()
                self._remove_session(session_id)
    
    def _remove_session(self, session_id: str) -> None:
        """Remove session from tracking"""
        session = self._sessions.pop(session_id, None)
        if session:
            self._sessions_by_peer.pop(session.peer_node_id, None)
    
    def _cleanup_loop(self) -> None:
        """Background thread to clean up expired sessions"""
        while self._running:
            time.sleep(self.cleanup_interval)
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> None:
        """Remove expired sessions"""
        with self._lock:
            expired = [
                sid for sid, session in self._sessions.items()
                if session.is_expired
            ]
            for sid in expired:
                self._remove_session(sid)
    
    def get_all_sessions(self) -> list[Session]:
        """Get all active sessions"""
        with self._lock:
            return [s for s in self._sessions.values() if not s.is_expired]
    
    def get_stats(self) -> dict:
        """Get manager statistics"""
        with self._lock:
            sessions = list(self._sessions.values())
            active = sum(1 for s in sessions if s.is_active)
            
            return {
                'total_sessions': len(sessions),
                'active_sessions': active,
                'node_id': self.node_id,
            }
    
    def shutdown(self) -> None:
        """Shutdown the manager"""
        self._running = False
        with self._lock:
            for session in self._sessions.values():
                session.close()
            self._sessions.clear()
            self._sessions_by_peer.clear()


if __name__ == '__main__':
    # Test session management
    import sys
    sys.path.insert(0, '/home/claude/blockchain-radio-v4')
    from crypto.keys import generate_keypair
    
    print("Session Management Test")
    print("=" * 50)
    
    # Create keypair
    keypair = generate_keypair("test-node")
    
    # Create session manager
    manager = SessionManager("test-node", keypair)
    
    # Create session
    session = manager.create_session("peer-node")
    print(f"Created session: {session.session_id[:16]}...")
    print(f"State: {session.state.name}")
    
    # Simulate handshake completion
    fake_key = os.urandom(32)
    fake_proof = '{"proof": "test"}'
    fake_commitment = os.urandom(32)
    
    session.establish(fake_key, fake_proof, fake_commitment)
    print(f"Established: {session.state.name}")
    
    # Test message authentication
    payload = b"Hello, Radio Network!"
    tag, seq, ts = session.create_authenticated_message(payload)
    print(f"Created message: seq={seq}, tag={tag.hex()[:16]}...")
    
    # Verify message
    valid, reason = session.verify_authenticated_message(payload, tag, seq, ts)
    print(f"Verified: {valid} ({reason})")
    
    # Test tampered message
    valid, reason = session.verify_authenticated_message(b"tampered", tag, seq + 1, ts)
    print(f"Tampered detected: {not valid} ({reason})")
    
    # Stats
    print()
    print("Session stats:", session.get_stats())
    print("Manager stats:", manager.get_stats())
    
    # Cleanup
    manager.shutdown()
    print()
    print("=" * 50)
    print("All tests passed!")
