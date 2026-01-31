"""
Session Cache for Blockchain Radio V4

Provides fast session lookup for repeaters:
- Caches verified session keys for HMAC verification
- Stores ZK proof commitments for audit
- Automatic expiration of stale sessions
- Thread-safe operations

This is what makes real-time messaging possible after handshake.
Repeaters cache session info after initial ZK verification,
enabling O(1) HMAC verification for all subsequent messages.
"""

import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Dict, Set
import json


@dataclass
class CachedSession:
    """
    Cached session information for fast verification
    
    Contains only what's needed for HMAC verification:
    - hmac_key: For computing/verifying HMAC tags
    - proof_hash: For binding verification (every HMAC must match this)
    - zk_commitment: Original ZK commitment (for audit)
    
    The key insight: We don't cache the full proof (~10KB).
    We cache proof_hash (32 bytes) which is included in every HMAC.
    Verification = HMAC valid + proof_hash matches cached value.
    """
    session_id: str
    node_id: str          # Original node that established session
    peer_node_id: str     # Peer node
    
    # HMAC key for verification (derived from session key)
    hmac_key: bytes
    
    # CRITICAL: Hash of the ZK proof - this is what we verify against
    # Every incoming message's HMAC includes a proof_hash
    # We verify: HMAC(key, proof_hash || ... || data) matches
    proof_hash: bytes
    
    # ZK proof commitment (for audit/verification)
    zk_commitment: bytes
    
    # State tracking
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    verified_at: float = field(default_factory=time.time)
    
    # Sequence tracking (for replay protection)
    last_seen_seq: int = 0
    
    # Configuration
    timeout_seconds: float = 3600.0
    
    # Statistics
    messages_verified: int = 0
    verification_failures: int = 0
    
    @property
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        age = time.time() - self.created_at
        return age > self.timeout_seconds
    
    @property
    def is_stale(self) -> bool:
        """Check if entry is stale (not used recently)"""
        idle = time.time() - self.last_used
        return idle > (self.timeout_seconds / 2)
    
    def touch(self) -> None:
        """Update last used timestamp"""
        self.last_used = time.time()
    
    def record_verification(self, success: bool, seq: int) -> None:
        """Record verification attempt"""
        self.touch()
        if success:
            self.messages_verified += 1
            if seq > self.last_seen_seq:
                self.last_seen_seq = seq
        else:
            self.verification_failures += 1
    
    def to_dict(self) -> dict:
        """Serialize to dictionary (excludes keys)"""
        return {
            'session_id': self.session_id,
            'node_id': self.node_id,
            'peer_node_id': self.peer_node_id,
            'created_at': self.created_at,
            'last_used': self.last_used,
            'messages_verified': self.messages_verified,
            'verification_failures': self.verification_failures,
            'last_seen_seq': self.last_seen_seq,
        }


class SessionCache:
    """
    Thread-safe session cache for repeaters
    
    Provides O(1) session lookup for fast HMAC verification.
    Sessions are cached after initial ZK proof verification.
    """
    
    def __init__(
        self,
        node_id: str,
        max_sessions: int = 10000,
        cleanup_interval: float = 60.0,
        default_timeout: float = 3600.0
    ):
        self.node_id = node_id
        self.max_sessions = max_sessions
        self.cleanup_interval = cleanup_interval
        self.default_timeout = default_timeout
        
        self._sessions: Dict[str, CachedSession] = {}
        self._sessions_by_node: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()
        
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True
        )
        self._cleanup_thread.start()
    
    def add_session(
        self,
        session_id: str,
        node_id: str,
        peer_node_id: str,
        hmac_key: bytes,
        proof_hash: bytes,
        zk_commitment: bytes,
        timeout: Optional[float] = None
    ) -> CachedSession:
        """
        Add a verified session to the cache
        
        Called AFTER ZK proof verification succeeds.
        
        Args:
            session_id: Unique session identifier
            node_id: Node that established the session
            peer_node_id: Peer node
            hmac_key: Derived HMAC key for verification
            proof_hash: SHA256(zk_proof) - THE CRITICAL BINDING
            zk_commitment: ZK proof commitment
            timeout: Optional custom timeout
        
        Returns:
            CachedSession object
        """
        with self._lock:
            if len(self._sessions) >= self.max_sessions:
                self._evict_oldest()
            
            cached = CachedSession(
                session_id=session_id,
                node_id=node_id,
                peer_node_id=peer_node_id,
                hmac_key=hmac_key,
                proof_hash=proof_hash,
                zk_commitment=zk_commitment,
                timeout_seconds=timeout or self.default_timeout
            )
            
            self._sessions[session_id] = cached
            
            if node_id not in self._sessions_by_node:
                self._sessions_by_node[node_id] = set()
            self._sessions_by_node[node_id].add(session_id)
            
            return cached
    
    def get_session(self, session_id: str) -> Optional[CachedSession]:
        """Get cached session by ID"""
        with self._lock:
            cached = self._sessions.get(session_id)
            
            if cached is None:
                self._misses += 1
                return None
            
            if cached.is_expired:
                self._remove_session(session_id)
                self._misses += 1
                return None
            
            self._hits += 1
            cached.touch()
            return cached
    
    def get_sessions_for_node(self, node_id: str) -> list[CachedSession]:
        """Get all cached sessions for a node"""
        with self._lock:
            session_ids = self._sessions_by_node.get(node_id, set())
            sessions = []
            
            for sid in list(session_ids):
                cached = self._sessions.get(sid)
                if cached and not cached.is_expired:
                    sessions.append(cached)
                else:
                    self._remove_session(sid)
            
            return sessions
    
    def has_session(self, session_id: str) -> bool:
        """Check if session exists and is valid"""
        with self._lock:
            cached = self._sessions.get(session_id)
            return cached is not None and not cached.is_expired
    
    def remove_session(self, session_id: str) -> bool:
        """Remove a session from cache"""
        with self._lock:
            return self._remove_session(session_id)
    
    def _remove_session(self, session_id: str) -> bool:
        """Internal: Remove session (must hold lock)"""
        cached = self._sessions.pop(session_id, None)
        if cached:
            node_sessions = self._sessions_by_node.get(cached.node_id)
            if node_sessions:
                node_sessions.discard(session_id)
                if not node_sessions:
                    del self._sessions_by_node[cached.node_id]
            return True
        return False
    
    def _evict_oldest(self) -> None:
        """Evict oldest session (must hold lock)"""
        if not self._sessions:
            return
        
        oldest_id = None
        oldest_time = float('inf')
        
        for sid, cached in self._sessions.items():
            if cached.last_used < oldest_time:
                oldest_time = cached.last_used
                oldest_id = sid
        
        if oldest_id:
            self._remove_session(oldest_id)
            self._evictions += 1
    
    def _cleanup_loop(self) -> None:
        """Background thread to clean up expired sessions"""
        while self._running:
            time.sleep(self.cleanup_interval)
            self._cleanup_expired()
    
    def _cleanup_expired(self) -> None:
        """Remove expired sessions"""
        with self._lock:
            expired = [
                sid for sid, cached in self._sessions.items()
                if cached.is_expired
            ]
            for sid in expired:
                self._remove_session(sid)
    
    def clear(self) -> None:
        """Clear all cached sessions"""
        with self._lock:
            self._sessions.clear()
            self._sessions_by_node.clear()
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        with self._lock:
            total_sessions = len(self._sessions)
            active_sessions = sum(
                1 for s in self._sessions.values() 
                if not s.is_expired and not s.is_stale
            )
            total_verified = sum(s.messages_verified for s in self._sessions.values())
            total_failures = sum(s.verification_failures for s in self._sessions.values())
            
            hit_rate = self._hits / (self._hits + self._misses) if (self._hits + self._misses) > 0 else 0
            
            return {
                'node_id': self.node_id,
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'cache_hits': self._hits,
                'cache_misses': self._misses,
                'hit_rate': hit_rate,
                'evictions': self._evictions,
                'total_messages_verified': total_verified,
                'total_verification_failures': total_failures,
            }
    
    def shutdown(self) -> None:
        """Shutdown the cache"""
        self._running = False
        self.clear()
    
    def export_sessions(self) -> list[dict]:
        """Export all sessions for debugging"""
        with self._lock:
            return [s.to_dict() for s in self._sessions.values()]


if __name__ == '__main__':
    import os
    
    print("Session Cache Test")
    print("=" * 50)
    
    cache = SessionCache(node_id="test-repeater")
    
    print("\n1. Adding sessions...")
    for i in range(5):
        session_id = f"session-{i}"
        hmac_key = os.urandom(32)
        commitment = os.urandom(32)
        
        cached = cache.add_session(
            session_id=session_id,
            node_id=f"node-{i}",
            peer_node_id=f"peer-{i}",
            hmac_key=hmac_key,
            zk_commitment=commitment
        )
        print(f"   Added: {session_id}")
    
    print("\n2. Looking up sessions...")
    for i in range(7):
        session_id = f"session-{i}"
        cached = cache.get_session(session_id)
        if cached:
            print(f"   Found: {session_id}")
        else:
            print(f"   Miss: {session_id}")
    
    print("\n3. Recording verifications...")
    cached = cache.get_session("session-0")
    if cached:
        for seq in range(1, 11):
            cached.record_verification(success=True, seq=seq)
        print(f"   Messages verified: {cached.messages_verified}")
        print(f"   Last seq: {cached.last_seen_seq}")
    
    print("\n4. Cache statistics:")
    stats = cache.get_stats()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.2%}")
        else:
            print(f"   {key}: {value}")
    
    cache.shutdown()
    print()
    print("=" * 50)
    print("Cache test completed!")
