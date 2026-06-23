# Blockchain Radio V3 - Session-Based ZK Authentication

## Overview

A real-time secure voice communication system using blockchain-based authentication with session optimization. Unlike V3 which required ZK proofs per message, V4 generates a single ZK-SNARK proof at session establishment, then uses fast HMAC verification for all subsequent messages.

## The Key Insight: proof_hash Binding

**The critical optimization is NOT just "use HMAC instead of ZK proofs."**

The insight is: **Every HMAC includes a hash of the original ZK proof**, creating a cryptographic binding chain:

```
Session Establishment (one-time, ~120s):
┌─────────────────────────────────────────────────────────┐
│  ZK Proof Generated → proof_hash = SHA256(full_proof)   │
│  Full proof (~10KB) verified once, then discarded       │
│  proof_hash (32 bytes) cached at all nodes              │
└─────────────────────────────────────────────────────────┘

Real-time Messages (ongoing, ~0.1ms each):
┌─────────────────────────────────────────────────────────┐
│  HMAC = HMAC(key, proof_hash || session || seq || data) │
│                      ↑                                  │
│         This binds EVERY message to the ZK proof        │
│                                                         │
│  Packet carries: data + hmac_tag + proof_hash (32B)     │
│  NOT the full ZK proof (10KB)                           │
└─────────────────────────────────────────────────────────┘

Verification at Repeaters:
┌─────────────────────────────────────────────────────────┐
│  1. Check packet.proof_hash == cached.proof_hash        │
│  2. Verify HMAC(key, proof_hash || ...) matches tag     │
│  3. If both pass → message is from ZK-verified sender   │
└─────────────────────────────────────────────────────────┘
```

**Why this matters:**
- The ZK proof proves identity without revealing private key
- The proof_hash cryptographically binds every message to that proof
- Attackers can't forge messages without the session key
- Attackers can't hijack sessions because proof_hash must match
- We get ZK-level security with HMAC-level speed

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SESSION ESTABLISHMENT PHASE                          │
│                              (One-time, ~120s)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RadioA ──────► Producer ──────► Repeaters ──────► Receiver                │
│      │              │                  │                │                   │
│      │    Generate ZK-SNARK     Verify Proof      Verify Proof              │
│      │    Proof (~120s)         Cache Session     Establish Session         │
│      │              │                  │                │                   │
│      └──────────────┴──────────────────┴────────────────┘                   │
│                           Session Key Derived                               │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                        REAL-TIME MESSAGE PHASE                              │
│                              (Fast, ~0.1ms)                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   RadioA ──────► Producer ──────► Repeaters ──────► Receiver ──────► RadioB │
│      │              │                  │                │                   │
│      │    HMAC Sign       HMAC Verify (cached)   HMAC Verify                │
│      │    (~0.05ms)            (~0.1ms)            (~0.1ms)                 │
│      │              │                  │                │                   │
│      └──────────────┴──────────────────┴────────────────┘                   │
│                           Real-time Voice Data                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Improvements Over V3

| Aspect | V3 | V4 |
|--------|----|----|
| Proof Generation | Per message (~120s each) | Once per session (~120s total) |
| Message Verification | Full ZK verify (~30s) | HMAC verify (~0.1ms) |
| Latency | Minutes per message | Real-time after handshake |
| Practical Use | Demo only | Production-ready |

## Directory Structure

```
blockchain-radio-v4/
├── crypto/                     # Cryptographic primitives
│   ├── __init__.py
│   ├── keys.py                 # Ed25519 key management
│   ├── hmac_auth.py            # HMAC-BLAKE2b authentication
│   └── key_derivation.py       # Session key derivation (HKDF)
├── session/                    # Session management
│   ├── __init__.py
│   ├── session.py              # Session state and lifecycle
│   ├── handshake.py            # ZK-SNARK handshake protocol
│   └── cache.py                # Session cache for repeaters
├── network/                    # Network nodes
│   ├── __init__.py
│   ├── packet.py               # Packet structure with session support
│   ├── producer.py             # Producer with session establishment
│   ├── repeater.py             # Repeater with session cache
│   └── receiver.py             # Receiver with session validation
├── zkapp/                      # ZK-SNARK smart contracts
│   ├── src/
│   │   ├── SessionProof.ts     # Session establishment proof
│   │   └── index.ts            # Exports
│   ├── package.json
│   └── tsconfig.json
├── radio/                      # Radio endpoints
│   ├── radio_a.py              # Sender radio
│   └── radio_b.py              # Receiver radio
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Protocol Flow

### Phase 1: Session Handshake (One-time)

1. **RadioA** sends HELLO to Producer
2. **Producer** generates ZK-SNARK proof (~120s)
   - Proves identity without revealing private key
   - Creates session commitment
3. **Producer** sends SESSION_INIT to Repeaters
4. **Repeaters** verify ZK proof, cache session
5. **Session established** with derived symmetric key

### Phase 2: Real-time Messages

1. **RadioA** sends voice data to Producer
2. **Producer** creates HMAC using session key (~0.05ms)
3. **Repeaters** verify HMAC from cache (~0.1ms)
4. **Receiver** delivers to RadioB
5. **Total latency**: <1ms after handshake

## Running with Docker

```bash
# Build all containers
docker-compose build

# Start the network
docker-compose up

# In another terminal, view logs
docker-compose logs -f producer

# Stop
docker-compose down
```

## Security Properties

- **Authentication**: ZK-SNARK proves identity without revealing secrets
- **Integrity**: HMAC-BLAKE2b ensures message integrity
- **Replay Protection**: Sequence numbers + timestamps
- **Forward Secrecy**: Session keys derived per session
- **Tamper Detection**: Any modification invalidates HMAC

## Performance Targets

- Session establishment: ~120 seconds (one-time)
- Message authentication: <0.1ms
- Message verification: <0.1ms
- End-to-end latency: <5ms (after session)
- Throughput: 1000+ messages/second

## Configuration

Environment variables:
- `SESSION_TIMEOUT`: Session duration (default: 3600s)
- `HMAC_ALGORITHM`: blake2b or sha256 (default: blake2b)
- `NODE_ID`: Unique node identifier
- `NEXT_HOP`: Next node address (host:port)
