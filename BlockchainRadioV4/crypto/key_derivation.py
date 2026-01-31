"""
Key Derivation for Blockchain Radio V4

Uses HKDF (HMAC-based Key Derivation Function) to derive:
- Session keys from ZK proof commitments
- HMAC keys for message authentication
- Encryption keys (future: for encrypted messages)

HKDF provides:
- Cryptographically secure key derivation
- Key separation (different keys for different purposes)
- Forward secrecy when combined with ephemeral inputs
"""

import hashlib
import hmac
import struct
import os
from typing import Tuple, Optional


def hkdf_extract(salt: bytes, input_key_material: bytes, hash_algo: str = 'sha256') -> bytes:
    """
    HKDF Extract phase - derive PRK from input key material
    
    Args:
        salt: Random value (can be empty)
        input_key_material: Source key material
        hash_algo: Hash algorithm to use
    
    Returns:
        Pseudorandom key (PRK)
    """
    if not salt:
        # If no salt, use zeros of hash length
        hash_len = hashlib.new(hash_algo).digest_size
        salt = b'\x00' * hash_len
    
    return hmac.new(salt, input_key_material, hash_algo).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int, hash_algo: str = 'sha256') -> bytes:
    """
    HKDF Expand phase - expand PRK to desired length
    
    Args:
        prk: Pseudorandom key from extract
        info: Application-specific context
        length: Desired output length
        hash_algo: Hash algorithm to use
    
    Returns:
        Derived key material of specified length
    """
    hash_len = hashlib.new(hash_algo).digest_size
    
    if length > 255 * hash_len:
        raise ValueError(f"Cannot derive more than {255 * hash_len} bytes")
    
    # Number of blocks needed
    n_blocks = (length + hash_len - 1) // hash_len
    
    # Generate blocks
    okm = b''
    t = b''
    
    for i in range(1, n_blocks + 1):
        t = hmac.new(prk, t + info + bytes([i]), hash_algo).digest()
        okm += t
    
    return okm[:length]


def hkdf(
    input_key_material: bytes,
    length: int,
    salt: bytes = b'',
    info: bytes = b'',
    hash_algo: str = 'sha256'
) -> bytes:
    """
    Full HKDF: Extract-then-Expand
    
    Args:
        input_key_material: Source key material
        length: Desired output length
        salt: Optional random value
        info: Application-specific context
        hash_algo: Hash algorithm
    
    Returns:
        Derived key of specified length
    """
    prk = hkdf_extract(salt, input_key_material, hash_algo)
    return hkdf_expand(prk, info, length, hash_algo)


def derive_session_key(
    zk_proof_commitment: bytes,
    node_public_key: bytes,
    session_nonce: bytes,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Derive session key from ZK proof commitment
    
    The session key is derived from:
    - ZK proof commitment (proves identity)
    - Node public key (binds to specific node)
    - Session nonce (ensures uniqueness)
    
    Args:
        zk_proof_commitment: Commitment from ZK-SNARK proof
        node_public_key: Ed25519 public key of the node
        session_nonce: Random nonce for this session
        salt: Optional additional salt
    
    Returns:
        32-byte session key
    """
    # Combine all inputs
    ikm = zk_proof_commitment + node_public_key + session_nonce
    
    # Use node public key hash as salt if not provided
    if salt is None:
        salt = hashlib.sha256(b'BlockchainRadioV4:SessionKey:' + node_public_key).digest()
    
    # Info string for key separation
    info = b'BlockchainRadioV4:SessionKey:v1'
    
    return hkdf(ikm, 32, salt, info)


def derive_hmac_key(session_key: bytes, purpose: str = 'message_auth') -> bytes:
    """
    Derive HMAC key from session key
    
    Uses HKDF to derive purpose-specific keys from the main session key.
    This allows using different keys for different operations.
    
    Args:
        session_key: Main session key
        purpose: Key purpose identifier
    
    Returns:
        32-byte HMAC key
    """
    info = f'BlockchainRadioV4:HMAC:{purpose}'.encode('utf-8')
    return hkdf(session_key, 32, info=info)


def derive_multiple_keys(
    session_key: bytes,
    key_specs: list[Tuple[str, int]]
) -> dict[str, bytes]:
    """
    Derive multiple keys from a single session key
    
    Args:
        session_key: Main session key
        key_specs: List of (purpose, length) tuples
    
    Returns:
        Dictionary mapping purpose to derived key
    """
    keys = {}
    
    for purpose, length in key_specs:
        info = f'BlockchainRadioV4:{purpose}'.encode('utf-8')
        keys[purpose] = hkdf(session_key, length, info=info)
    
    return keys


def derive_session_keys(session_key: bytes) -> dict[str, bytes]:
    """
    Derive all standard keys for a session
    
    Returns a dictionary with:
    - hmac_key: For message authentication
    - encryption_key: For message encryption (future use)
    - nonce_key: For generating per-message nonces
    
    Args:
        session_key: Main session key
    
    Returns:
        Dictionary of derived keys
    """
    return derive_multiple_keys(session_key, [
        ('hmac', 32),
        ('encryption', 32),
        ('nonce', 16),
    ])


def generate_session_nonce() -> bytes:
    """Generate a random session nonce"""
    return os.urandom(32)


def create_session_commitment(
    node_id: str,
    public_key: bytes,
    timestamp: float,
    nonce: bytes
) -> bytes:
    """
    Create a commitment for ZK proof
    
    This commitment is what gets proved in the ZK-SNARK.
    It commits to the node's identity without revealing the private key.
    
    Args:
        node_id: Node identifier
        public_key: Node's Ed25519 public key
        timestamp: Session start timestamp
        nonce: Random session nonce
    
    Returns:
        32-byte commitment hash
    """
    data = struct.pack(
        f'!H{len(node_id)}s32sd32s',
        len(node_id),
        node_id.encode('utf-8'),
        public_key,
        timestamp,
        nonce
    )
    return hashlib.sha256(data).digest()


def verify_session_commitment(
    commitment: bytes,
    node_id: str,
    public_key: bytes,
    timestamp: float,
    nonce: bytes
) -> bool:
    """
    Verify a session commitment
    
    Args:
        commitment: Commitment to verify
        node_id: Expected node ID
        public_key: Expected public key
        timestamp: Expected timestamp
        nonce: Expected nonce
    
    Returns:
        True if commitment matches, False otherwise
    """
    expected = create_session_commitment(node_id, public_key, timestamp, nonce)
    return hmac.compare_digest(commitment, expected)


if __name__ == '__main__':
    import time
    
    print("Key Derivation Benchmark")
    print("=" * 50)
    
    # Test inputs
    proof_commitment = hashlib.sha256(b'zk-proof-commitment').digest()
    public_key = hashlib.sha256(b'node-public-key').digest()
    nonce = generate_session_nonce()
    
    # Benchmark session key derivation
    iterations = 10000
    start = time.time()
    for _ in range(iterations):
        session_key = derive_session_key(proof_commitment, public_key, nonce)
    derive_time = (time.time() - start) / iterations * 1000
    print(f"Session key derivation: {derive_time:.4f}ms")
    
    # Benchmark HMAC key derivation
    start = time.time()
    for _ in range(iterations):
        hmac_key = derive_hmac_key(session_key)
    hmac_derive_time = (time.time() - start) / iterations * 1000
    print(f"HMAC key derivation: {hmac_derive_time:.4f}ms")
    
    # Derive all session keys
    print()
    print("Derived keys:")
    keys = derive_session_keys(session_key)
    for purpose, key in keys.items():
        print(f"  {purpose}: {key.hex()[:32]}...")
    
    # Test commitment
    print()
    print("Commitment tests:")
    commitment = create_session_commitment('node-123', public_key, time.time(), nonce)
    print(f"  Commitment: {commitment.hex()[:32]}...")
    
    # Verify commitment
    valid = verify_session_commitment(
        commitment, 'node-123', public_key, time.time(), nonce
    )
    # Note: This will fail because timestamp changed
    print(f"  Fresh verification: {valid}")
    
    print()
    print("=" * 50)
    print("All benchmarks completed!")
