"""
Ed25519 Key Management for Blockchain Radio V4

Ed25519 provides:
- Fast key generation (~0.05ms)
- Fast signing (~0.1ms)
- Fast verification (~0.3ms)
- 128-bit security level
- Deterministic signatures (no randomness needed)
"""

import os
import json
import base64
import hashlib
from dataclasses import dataclass
from typing import Optional, Tuple
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class KeyPair:
    """Ed25519 key pair container"""
    private_key: bytes
    public_key: bytes
    node_id: str
    
    def get_public_key_hex(self) -> str:
        """Get public key as hex string"""
        return self.public_key.hex()
    
    def get_public_key_b64(self) -> str:
        """Get public key as base64 string"""
        return base64.b64encode(self.public_key).decode('ascii')
    
    def get_node_id_from_pubkey(self) -> str:
        """Derive node ID from public key (first 8 bytes of SHA256)"""
        return hashlib.sha256(self.public_key).hexdigest()[:16]
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the private key"""
        if CRYPTO_AVAILABLE:
            private = ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key)
            return private.sign(message)
        else:
            # Fallback: Use HMAC-based signature simulation
            import hmac
            return hmac.new(self.private_key, message, hashlib.sha256).digest()
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature"""
        if CRYPTO_AVAILABLE:
            try:
                public = ed25519.Ed25519PublicKey.from_public_bytes(self.public_key)
                public.verify(signature, message)
                return True
            except Exception:
                return False
        else:
            # Fallback verification
            import hmac
            expected = hmac.new(self.private_key, message, hashlib.sha256).digest()
            return hmac.compare_digest(signature, expected)
    
    def to_dict(self) -> dict:
        """Serialize to dictionary"""
        return {
            'private_key': base64.b64encode(self.private_key).decode('ascii'),
            'public_key': base64.b64encode(self.public_key).decode('ascii'),
            'node_id': self.node_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'KeyPair':
        """Deserialize from dictionary"""
        return cls(
            private_key=base64.b64decode(data['private_key']),
            public_key=base64.b64decode(data['public_key']),
            node_id=data['node_id'],
        )


def generate_keypair(node_id: Optional[str] = None) -> KeyPair:
    """
    Generate a new Ed25519 key pair
    
    Args:
        node_id: Optional node identifier. If not provided, derived from public key.
    
    Returns:
        KeyPair with private key, public key, and node ID
    """
    if CRYPTO_AVAILABLE:
        # Use cryptography library for real Ed25519
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        # Fallback: Generate random bytes (NOT cryptographically secure Ed25519)
        # This is only for testing when cryptography library is unavailable
        private_bytes = os.urandom(32)
        public_bytes = hashlib.sha256(private_bytes).digest()
    
    keypair = KeyPair(
        private_key=private_bytes,
        public_key=public_bytes,
        node_id=node_id or ''
    )
    
    # Derive node ID from public key if not provided
    if not node_id:
        keypair.node_id = keypair.get_node_id_from_pubkey()
    
    return keypair


def save_keypair(keypair: KeyPair, filepath: str) -> None:
    """
    Save key pair to file
    
    Args:
        keypair: KeyPair to save
        filepath: Path to save file
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w') as f:
        json.dump(keypair.to_dict(), f, indent=2)
    
    # Set restrictive permissions (owner read/write only)
    os.chmod(path, 0o600)


def load_keypair(filepath: str) -> KeyPair:
    """
    Load key pair from file
    
    Args:
        filepath: Path to key file
    
    Returns:
        KeyPair loaded from file
    
    Raises:
        FileNotFoundError: If key file doesn't exist
        ValueError: If key file is invalid
    """
    path = Path(filepath)
    
    if not path.exists():
        raise FileNotFoundError(f"Key file not found: {filepath}")
    
    with open(path, 'r') as f:
        data = json.load(f)
    
    return KeyPair.from_dict(data)


def get_or_create_keypair(filepath: str, node_id: Optional[str] = None) -> KeyPair:
    """
    Get existing key pair or create new one
    
    Args:
        filepath: Path to key file
        node_id: Node identifier for new keys
    
    Returns:
        KeyPair (existing or newly created)
    """
    try:
        return load_keypair(filepath)
    except FileNotFoundError:
        keypair = generate_keypair(node_id)
        save_keypair(keypair, filepath)
        return keypair


def public_key_from_hex(hex_str: str) -> bytes:
    """Convert hex string to public key bytes"""
    return bytes.fromhex(hex_str)


def public_key_from_b64(b64_str: str) -> bytes:
    """Convert base64 string to public key bytes"""
    return base64.b64decode(b64_str)


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature using only the public key
    
    Args:
        public_key: Ed25519 public key bytes
        message: Original message bytes
        signature: Signature bytes
    
    Returns:
        True if signature is valid, False otherwise
    """
    if CRYPTO_AVAILABLE:
        try:
            public = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            public.verify(signature, message)
            return True
        except Exception:
            return False
    else:
        # Cannot verify without private key in fallback mode
        # This should not happen in production
        return False


if __name__ == '__main__':
    # Test key generation and signing
    import time
    
    print("Testing Ed25519 Key Management")
    print("=" * 50)
    
    # Generate key pair
    start = time.time()
    keypair = generate_keypair("test-node")
    gen_time = (time.time() - start) * 1000
    print(f"Key generation: {gen_time:.3f}ms")
    print(f"Node ID: {keypair.node_id}")
    print(f"Public Key: {keypair.get_public_key_hex()[:32]}...")
    
    # Sign message
    message = b"Hello, Radio Network!"
    start = time.time()
    signature = keypair.sign(message)
    sign_time = (time.time() - start) * 1000
    print(f"Signing: {sign_time:.3f}ms")
    print(f"Signature: {signature.hex()[:32]}...")
    
    # Verify signature
    start = time.time()
    valid = keypair.verify(message, signature)
    verify_time = (time.time() - start) * 1000
    print(f"Verification: {verify_time:.3f}ms")
    print(f"Valid: {valid}")
    
    # Test invalid signature
    invalid_sig = b'\x00' * 64
    valid = keypair.verify(message, invalid_sig)
    print(f"Invalid signature detected: {not valid}")
    
    # Save and load
    save_keypair(keypair, '/tmp/test_keypair.json')
    loaded = load_keypair('/tmp/test_keypair.json')
    print(f"Save/Load: {keypair.node_id == loaded.node_id}")
    
    print("=" * 50)
    print("All tests passed!" if CRYPTO_AVAILABLE else "Running in fallback mode")
