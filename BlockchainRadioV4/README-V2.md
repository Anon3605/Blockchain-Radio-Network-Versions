# Blockchain Radio V4 - Decentralized Radio Mesh Authentication

## What Makes This Architecture Unique

This is **not** just "adding blockchain to radios." This architecture solves a fundamental problem:

> **How do you authenticate radio nodes in a mesh network without a central authority, while maintaining real-time performance?**

### The Problem with Existing Solutions

| System | Authentication | Central Authority | Real-time |
|--------|---------------|-------------------|-----------|
| P25 (AES-256) | Pre-shared keys | Yes (key server) | ✓ |
| DMR | Pre-shared keys | Yes (key server) | ✓ |
| TLS/SSL | Certificates | Yes (CA) | ✓ |
| Basic ZK-SNARK | Per-message proofs | No | ✗ (~120s/msg) |
| **This System** | Session + HMAC | No | ✓ |

### The Core Innovation: Dual-Layer Separation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DUAL-LAYER ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 1: BLOCKCHAIN GOSSIP (Control Plane) - TCP 7xxx                     │
│  ═══════════════════════════════════════════════                           │
│  Purpose: Session establishment, ZK proof propagation, consensus            │
│  Topology: FULL MESH (everyone ↔ everyone)                                 │
│  Traffic: LOW (only on session start/end)                                  │
│  Protocol: Gossip over TCP                                                 │
│                                                                             │
│       Producer ◄────► Repeater1 ◄────► Repeater2                           │
│           │              │               │                                 │
│           ▼              ▼               ▼                                 │
│       Repeater3 ◄────► Repeater4 ◄────► Receiver                           │
│                    (full mesh)                                             │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  LAYER 2: DATA FORWARDING (Data Plane) - TCP 5xxx, UDP                     │
│  ═══════════════════════════════════════════════════                       │
│  Purpose: Real-time voice/data with HMAC verification                      │
│  Topology: LINEAR CHAIN (hop-by-hop)                                       │
│  Traffic: HIGH (all voice/data messages)                                   │
│  Protocol: TCP between nodes, UDP for radio endpoints                      │
│                                                                             │
│  RadioA → Producer → Rep1 → Rep2 → Rep3 → Rep4 → Receiver → RadioB        │
│     UDP      TCP      TCP    TCP    TCP    TCP      TCP       UDP          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Why This Matters

### 1. **The Repeaters ARE the Blockchain**

There is no external blockchain network. The mesh nodes themselves maintain the distributed ledger:

```
Traditional Blockchain Radio:
  Radio Mesh ──────► External Blockchain (Ethereum, etc.)
                           │
                     Single point of failure
                     External dependency
                     Network latency

This Architecture:
  ┌─────────────────────────────────────┐
  │          RADIO MESH                 │
  │  Producer + Repeaters + Receiver    │
  │         ═══════════════            │
  │    ARE the blockchain nodes         │
  │                                     │
  │  No external dependency             │
  │  No single point of failure         │
  │  Self-contained trust               │
  └─────────────────────────────────────┘
```

### 2. **Gossip Protocol for Session Propagation**

When a session is established:

```
1. Producer generates ZK proof for RadioA
2. Producer broadcasts SESSION_ANNOUNCE via gossip (Layer 1)
3. All nodes receive, verify, and cache the session
4. Consensus: Majority of nodes must verify
5. Session is "committed" to the distributed ledger
6. Now ALL nodes can verify messages from this session (Layer 2)
```

### 3. **proof_hash Binding - The Security Link**

The ZK proof is verified ONCE, but its hash binds EVERY message:

```
Session Establishment (Layer 1):
┌─────────────────────────────────────────────────────────────┐
│  1. ZK Proof generated (~120s)                              │
│  2. proof_hash = SHA256(full_proof)                         │
│  3. proof_hash gossiped to ALL nodes                        │
│  4. Nodes cache: session_id → {proof_hash, hmac_key}        │
│  5. Full proof can be discarded                             │
└─────────────────────────────────────────────────────────────┘

Real-time Messages (Layer 2):
┌─────────────────────────────────────────────────────────────┐
│  Every packet contains:                                     │
│    - data (voice/message)                                   │
│    - proof_hash (32 bytes) ← binds to ZK proof              │
│    - hmac_tag = HMAC(key, proof_hash || seq || data)        │
│                                                             │
│  Verification at each hop:                                  │
│    1. packet.proof_hash == cached.proof_hash? (~0.01ms)    │
│    2. HMAC valid? (~0.05ms)                                 │
│    3. Both pass → message from ZK-verified session          │
└─────────────────────────────────────────────────────────────┘
```

## Port Architecture (MIMO-Inspired)

Like radio MIMO (Multiple Input Multiple Output), we separate control and data:

| Node | Data Ports (5xxx/6xxx) | Blockchain Ports (7xxx) | Radio Ports (UDP) |
|------|------------------------|-------------------------|-------------------|
| RadioA | - | - | 54321 |
| RadioB | - | - | 54321 |
| Producer | UDP:12345, TCP:5000 | TCP:7000 (listen), 7001-7005 (out) | - |
| Repeater1 | TCP:5001 | TCP:7000 (listen), 7101-7105 (out) | - |
| Repeater2 | TCP:5002 | TCP:7000 (listen), 7201-7205 (out) | - |
| Repeater3 | TCP:5003 | TCP:7000 (listen), 7301-7305 (out) | - |
| Repeater4 | TCP:5004 | TCP:7000 (listen), 7401-7405 (out) | - |
| Receiver | TCP:6000 | TCP:7000 (listen), 7501-7505 (out) | - |

**Key insight**: Blockchain sync (7xxx) NEVER blocks data forwarding (5xxx). They run in parallel.

## Message Flow

### Session Establishment (One-time, ~120s)

```
┌─────────┐                    LAYER 1: GOSSIP NETWORK
│ RadioA  │                    ════════════════════════
└────┬────┘
     │ "I want to talk"
     ▼
┌─────────┐    gossip    ┌──────────┐    gossip    ┌──────────┐
│Producer │─────────────►│ Repeater1│─────────────►│ Repeater2│
│ :7000   │◄─────────────│  :7000   │◄─────────────│  :7000   │
└─────────┘              └──────────┘              └──────────┘
     │                        │                         │
     └────────────────────────┼─────────────────────────┘
                              │ (full mesh)
                              ▼
                    All nodes now have:
                    - session_id
                    - proof_hash
                    - hmac_key (derived)
```

### Real-time Data (Ongoing, ~0.1ms per hop)

```
┌─────────┐                    LAYER 2: DATA FORWARDING
│ RadioA  │                    ════════════════════════
└────┬────┘
     │ UDP voice data
     ▼
┌─────────┐  TCP   ┌──────────┐  TCP   ┌──────────┐  TCP   ┌──────────┐
│Producer │───────►│ Repeater1│───────►│ Repeater2│───────►│ Repeater3│
│ :5000   │        │  :5001   │        │  :5002   │        │  :5003   │
└─────────┘        └──────────┘        └──────────┘        └──────────┘
                                                                 │
     ┌───────────────────────────────────────────────────────────┘
     │
     ▼
┌──────────┐  TCP   ┌──────────┐  UDP   ┌─────────┐
│ Repeater4│───────►│ Receiver │───────►│ RadioB  │
│  :5004   │        │  :6000   │        │ :54321  │
└──────────┘        └──────────┘        └─────────┘

At each hop: Check proof_hash + Verify HMAC (~0.1ms total)
No blockchain interaction!
```

## Security Properties

| Property | How It's Achieved |
|----------|-------------------|
| **Authentication** | ZK-SNARK proves identity without revealing private key |
| **Decentralization** | Gossip protocol - no central authority |
| **Integrity** | HMAC on every message |
| **Binding** | proof_hash in every HMAC links to ZK proof |
| **Replay Protection** | Sequence numbers + timestamps |
| **Real-time** | Session cached, only HMAC verification on data path |

## Performance

| Operation | Time | When |
|-----------|------|------|
| Session establishment | ~120s | Once per session |
| Gossip propagation | ~1-2s | Once per session |
| HMAC creation | ~0.003ms | Every message |
| HMAC verification | ~0.003ms | Every hop |
| **Total per-message latency** | **<1ms** | After session |

## Running the System

```bash
# Build
docker-compose -f docker-compose-v2.yml build

# Run
docker-compose -f docker-compose-v2.yml up

# Watch logs
docker-compose -f docker-compose-v2.yml logs -f producer

# Stop
docker-compose -f docker-compose-v2.yml down
```

## Project Structure

```
blockchain-radio-v4/
├── blockchain/           # Layer 1: Gossip network
│   ├── gossip.py        # Gossip protocol implementation
│   └── __init__.py
├── crypto/              # Cryptographic primitives
│   ├── keys.py          # Ed25519 key management
│   ├── hmac_auth.py     # HMAC-BLAKE2b with proof_hash binding
│   └── key_derivation.py # Session key derivation
├── session/             # Session management
│   ├── session.py       # Session lifecycle
│   ├── cache.py         # Fast session lookup
│   └── handshake.py     # ZK handshake protocol
├── network/             # Layer 2: Data forwarding
│   ├── packet.py        # Packet structures
│   ├── producer_v2.py   # Producer with dual-layer support
│   ├── repeater_v2.py   # Repeater with dual-layer support
│   └── receiver_v2.py   # Receiver with dual-layer support
├── radio/               # Radio endpoints
│   ├── radio_a.py       # Sender
│   └── radio_b.py       # Receiver
├── zkapp/               # ZK-SNARK contracts
│   └── src/
│       └── SessionProof.ts
├── docker-compose-v2.yml # Dual-layer deployment
└── README.md
```

## Contribution to the Field

This architecture demonstrates:

1. **ZK-SNARKs can be practical for real-time systems** through session-based optimization
2. **Radio mesh networks can be truly decentralized** without sacrificing performance
3. **Control/data plane separation** enables blockchain without blocking real-time traffic
4. **The mesh nodes themselves can form the blockchain** - no external dependency

This is applicable beyond radio: any mesh network (IoT, sensor networks, emergency communications) that needs decentralized trust without central key infrastructure.
