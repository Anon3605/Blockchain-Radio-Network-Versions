"""
Crypto module for Blockchain Radio V4

Provides lightweight cryptographic primitives optimized for real-time
communication after session establishment.

Components:
- keys: Ed25519 key generation and management
- hmac_auth: HMAC-BLAKE2b for fast message authentication
- key_derivation: HKDF for session key derivation
"""

from .keys import KeyPair, generate_keypair, load_keypair, save_keypair
from .hmac_auth import HMACAuth, create_hmac, verify_hmac
from .key_derivation import derive_session_key, derive_hmac_key

__all__ = [
    'KeyPair',
    'generate_keypair',
    'load_keypair', 
    'save_keypair',
    'HMACAuth',
    'create_hmac',
    'verify_hmac',
    'derive_session_key',
    'derive_hmac_key',
]
