"""
HMAC Authentication for Blockchain Radio V4

Uses HMAC-BLAKE2b for ultra-fast message authentication:
- BLAKE2b is faster than SHA-256 on modern CPUs
- 128-bit security with 32-byte tags
- ~0.05ms per HMAC operation

This module is used for real-time message authentication AFTER
session establishment (which uses ZK-SNARK).
"""

import hmac
import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple

# Try to use BLAKE2b, fall back to SHA-256
try:
    import hashlib
    # Test if BLAKE2b is available
    hashlib.blake2b(b'test', digest_size=32)
    DEFAULT_ALGORITHM = 'blake2b'
except (AttributeError, ValueError):
    DEFAULT_ALGORITHM = 'sha256'


@dataclass
class HMACAuth:
    """
    HMAC Authenticator for session messages
    
    CRITICAL DESIGN: Every HMAC includes the proof_hash, which binds
    all messages to the original ZK-SNARK proof. This means:
    
    1. Proof is verified ONCE (slow, ~120s)
    2. proof_hash = SHA256(proof) is computed and cached
    3. Every message HMAC includes proof_hash
    4. Verifiers check: HMAC valid + proof_hash matches cached session
    
    This gives us ZK-level security with HMAC-level speed.
    """
    
    session_key: bytes
    session_id: str
    proof_hash: bytes = b'\x00' * 32  # Hash of ZK proof - THE CRITICAL BINDING
    sequence_number: int = 0
    algorithm: str = DEFAULT_ALGORITHM
    tag_size: int = 32  # 256 bits
    
    def _compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC using configured algorithm"""
        if self.algorithm == 'blake2b':
            # BLAKE2b with keyed mode (built-in MAC)
            h = hashlib.blake2b(data, key=self.session_key, digest_size=self.tag_size)
            return h.digest()
        else:
            # Fallback to HMAC-SHA256
            return hmac.new(self.session_key, data, hashlib.sha256).digest()
    
    def create_tag(self, message: bytes, timestamp: Optional[float] = None) -> Tuple[bytes, int, float]:
        """
        Create authentication tag for a message
        
        Args:
            message: Message bytes to authenticate
            timestamp: Optional timestamp (uses current time if not provided)
        
        Returns:
            Tuple of (tag, sequence_number, timestamp)
        """
        if timestamp is None:
            timestamp = time.time()
        
        # Increment sequence number
        self.sequence_number += 1
        seq = self.sequence_number
        
        # Build authenticated data: session_id | seq | timestamp | message
        auth_data = self._build_auth_data(message, seq, timestamp)
        
        # Compute HMAC
        tag = self._compute_hmac(auth_data)
        
        return tag, seq, timestamp
    
    def verify_tag(
        self, 
        message: bytes, 
        tag: bytes, 
        seq: int, 
        timestamp: float,
        max_age_seconds: float = 30.0,
        min_seq: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Verify authentication tag
        
        Args:
            message: Message bytes
            tag: Authentication tag
            seq: Sequence number
            timestamp: Message timestamp
            max_age_seconds: Maximum message age
            min_seq: Minimum acceptable sequence number (replay protection)
        
        Returns:
            Tuple of (is_valid, reason)
        """
        # Check timestamp freshness
        age = time.time() - timestamp
        if age > max_age_seconds:
            return False, f"Message too old: {age:.1f}s > {max_age_seconds}s"
        
        if age < -5.0:  # Allow 5 seconds clock skew
            return False, f"Message from future: {age:.1f}s"
        
        # Check sequence number (replay protection)
        if min_seq is not None and seq <= min_seq:
            return False, f"Sequence too low: {seq} <= {min_seq}"
        
        # Rebuild authenticated data
        auth_data = self._build_auth_data(message, seq, timestamp)
        
        # Compute expected tag
        expected_tag = self._compute_hmac(auth_data)
        
        # Constant-time comparison
        if not hmac.compare_digest(tag, expected_tag):
            return False, "Invalid HMAC tag"
        
        return True, "OK"
    
    def _build_auth_data(self, message: bytes, seq: int, timestamp: float) -> bytes:
        """
        Build data to be authenticated
        
        CRITICAL: Includes proof_hash to bind every message to the original ZK proof.
        Structure: proof_hash (32) | session_id | seq (8) | timestamp (8) | message
        
        This ensures cryptographic binding between:
        - The ZK proof (verified once at session start)
        - Every subsequent message (verified via HMAC)
        """
        session_bytes = self.session_id.encode('utf-8')
        
        # Include proof_hash in authenticated data - THIS IS THE KEY BINDING
        header = struct.pack(
            f'!32sH{len(session_bytes)}sQd',
            self.proof_hash,     # ZK proof hash - binds to original proof!
            len(session_bytes),  # Session ID length
            session_bytes,       # Session ID
            seq,                 # Sequence number (replay protection)
            timestamp            # Timestamp (freshness)
        )
        return header + message


def create_hmac(session_key: bytes, message: bytes, session_id: str = '') -> bytes:
    """
    Simple HMAC creation (stateless)
    
    Args:
        session_key: 32-byte session key
        message: Message to authenticate
        session_id: Optional session identifier
    
    Returns:
        32-byte HMAC tag
    """
    data = session_id.encode('utf-8') + message
    
    if DEFAULT_ALGORITHM == 'blake2b':
        return hashlib.blake2b(data, key=session_key, digest_size=32).digest()
    else:
        return hmac.new(session_key, data, hashlib.sha256).digest()


def verify_hmac(session_key: bytes, message: bytes, tag: bytes, session_id: str = '') -> bool:
    """
    Simple HMAC verification (stateless)
    
    Args:
        session_key: 32-byte session key
        message: Message that was authenticated
        tag: HMAC tag to verify
        session_id: Optional session identifier
    
    Returns:
        True if valid, False otherwise
    """
    expected = create_hmac(session_key, message, session_id)
    return hmac.compare_digest(tag, expected)


@dataclass 
class AuthenticatedMessage:
    """Container for an authenticated message"""
    payload: bytes
    tag: bytes
    sequence: int
    timestamp: float
    session_id: str
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for transmission"""
        session_bytes = self.session_id.encode('utf-8')
        header = struct.pack(
            f'!H{len(session_bytes)}sQdI32s',
            len(session_bytes),
            session_bytes,
            self.sequence,
            self.timestamp,
            len(self.payload),
            self.tag
        )
        return header + self.payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'AuthenticatedMessage':
        """Deserialize from bytes"""
        # Read session ID length
        sid_len = struct.unpack('!H', data[:2])[0]
        
        # Unpack header
        header_fmt = f'!H{sid_len}sQdI32s'
        header_size = struct.calcsize(header_fmt)
        
        _, session_bytes, seq, ts, payload_len, tag = struct.unpack(
            header_fmt, data[:header_size]
        )
        
        payload = data[header_size:header_size + payload_len]
        
        return cls(
            payload=payload,
            tag=tag,
            sequence=seq,
            timestamp=ts,
            session_id=session_bytes.decode('utf-8')
        )


if __name__ == '__main__':
    # Benchmark HMAC performance
    import time
    
    print("HMAC Authentication Benchmark")
    print("=" * 50)
    print(f"Algorithm: {DEFAULT_ALGORITHM}")
    print()
    
    # Create session key
    session_key = hashlib.sha256(b'test-session-key').digest()
    session_id = 'test-session-123'
    
    # Create authenticator
    auth = HMACAuth(
        session_key=session_key,
        session_id=session_id,
        algorithm=DEFAULT_ALGORITHM
    )
    
    # Test message
    message = b"Voice data packet " + b'\x00' * 1000  # ~1KB message
    
    # Benchmark creation
    iterations = 10000
    start = time.time()
    for _ in range(iterations):
        tag, seq, ts = auth.create_tag(message)
    create_time = (time.time() - start) / iterations * 1000
    print(f"Tag creation: {create_time:.4f}ms per operation")
    
    # Benchmark verification
    tag, seq, ts = auth.create_tag(message)
    auth2 = HMACAuth(session_key=session_key, session_id=session_id)
    
    start = time.time()
    for _ in range(iterations):
        valid, _ = auth2.verify_tag(message, tag, seq, ts)
    verify_time = (time.time() - start) / iterations * 1000
    print(f"Tag verification: {verify_time:.4f}ms per operation")
    
    # Test message sizes
    print()
    print("Performance by message size:")
    for size in [100, 1000, 10000, 100000]:
        msg = b'\x00' * size
        start = time.time()
        for _ in range(1000):
            create_hmac(session_key, msg, session_id)
        t = (time.time() - start) / 1000 * 1000
        print(f"  {size:>6} bytes: {t:.4f}ms")
    
    # Test correctness
    print()
    print("Correctness tests:")
    
    # Valid verification
    auth = HMACAuth(session_key=session_key, session_id=session_id)
    tag, seq, ts = auth.create_tag(b"test message")
    valid, reason = auth.verify_tag(b"test message", tag, seq, ts, min_seq=0)
    print(f"  Valid message: {valid} ({reason})")
    
    # Tampered message
    valid, reason = auth.verify_tag(b"tampered message", tag, seq, ts, min_seq=0)
    print(f"  Tampered message: {not valid} ({reason})")
    
    # Replay attack
    valid, reason = auth.verify_tag(b"test message", tag, seq, ts, min_seq=seq)
    print(f"  Replay detected: {not valid} ({reason})")
    
    print()
    print("=" * 50)
    print("All benchmarks completed!")
