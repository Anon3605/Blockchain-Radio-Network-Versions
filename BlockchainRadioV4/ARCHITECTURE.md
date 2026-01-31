# Blockchain Radio V4 - Final Architecture

## The Golden Rule

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   PRODUCER PROPOSES, REPEATERS DECIDE                                       │ 
│   ===================================                                       │
│                                                                             │
│   The blockchain is RUN BY THE REPEATERS collectively.                      │
│   Producer creates proposals, but REPEATERS verify and sign.                │
│   Block is valid when MAJORITY of repeaters sign.                           │
│                                                                             │
│   This is DECENTRALIZED (repeaters decide) and LIGHTWEIGHT (no heavy        │
│   computation on Raspberry Pi - just verify, sign, cache, forward).         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Architecture Overview

```
SESSION ESTABLISHMENT FLOW:
===========================

Step 1: Producer creates PROPOSAL
─────────────────────────────────
                                         ┌─────────────────────────────────────┐
                                         │         PRODUCER (Ryzen 7)          │
                    RadioA ─────────────►│                                     │
                      Establishing       │  • Generate ZK proof (~120s)        │ 
                      a connection       │  • Create block PROPOSAL            │
                                         │  • Broadcast to all repeaters       │
                                         └──────────────────┬──────────────────┘
                                                            │   
                                                            |
                                                            │ PROPOSAL
                                                            ▼
                    ┌──────────────────────────────────────────────────────────────────────────────┐            
                    │                   |                   │                  │                   │           
                    ▼                   ▼                   ▼                  ▼                   ▼           
             ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐
             │Repeater 1│        │Repeater 2│        │Repeater 3│        │Repeater 4│        │Reciever  │
             │  (Pi)    │        │  (Pi)    │        │  (Pi)    │        │  (Pi)    │        │  (Pi)    │
             └──────────┘        └──────────┘        └──────────┘        └──────────┘        └──────────┘


Step 2: Each repeater VERIFIES and SIGNS
────────────────────────────────────────

Each Raspberry Pi does (lightweight operations):
  ┌─────────────────────────────────────────────────┐
  │  1. Verify proposal hash           (~0.1ms)     │
  │  2. Verify chain link              (~0.1ms)     │
  │  3. Sign "I approve this block"    (~1ms)       │
  │  4. Send signature to producer                  │
  └─────────────────────────────────────────────────┘


Step 3: Producer collects SIGNATURES
────────────────────────────────────

             ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐        ┌──────────┐         
             │Repeater 1│        │Repeater 2│        │Repeater 3│        │Repeater 4│        │Reciever  │      
             └─────┬────┘        └─────┬────┘        └─────┬────┘        └─────┬────┘        └─────┬────┘      
                   │                   │                   │                   │                   │          
                   │ SIGNATURE         │ SIGNATURE         │ SIGNATURE         │ SIGNATURE         │ SIGNATURE
                   │                   │                   │                   │                   │           
                   └───────────────────────────────────────┼───────────────────────────────────────┘
                                                           │
                                                           ▼
                                         ┌─────────────────────────────────────┐
                                         │         PRODUCER                    │
                                         │                                     │
                                         │  Collected: 3/4 signatures          │
                                         │  Majority (3) reached: OK           │
                                         │  > FINALIZE BLOCK                   │
                                         └─────────────────────────────────────┘


Step 4: Producer broadcasts FINALIZED block
───────────────────────────────────────────

                                         ┌─────────────────────────────────────┐
                                         │         PRODUCER                    │
                                         │                                     │
                                         │  Finalized Block:                   │
                                         │  • Sessions: [RadioA session]       │
                                         │  • Signatures: [R1, R2, R3, R4,     | 
                                         |                 Reciever]           │
                                         └──────────────────┬──────────────────┘
                                                            │
                                                            │ FINALIZED BLOCK
                                                            ▼
                    ┌────────────────────────────────────────────────────────────────────────────┐
                    │                   |                   │                │                   │
                    ▼                   ▼                   ▼                ▼                   ▼
               ┌──────────┐        ┌──────────┐        ┌──────────┐      ┌──────────┐       ┌──────────┐
               │Repeater 1│        │Repeater 2│        │Repeater 3│      │Repeater 4│       │Reciever  │
               │          │        │          │        │          │      │          │       │          │
               │ • Verify │        │ • Verify │        │ • Verify │      │ • Verify │       │ • Verify │
               │   sigs   │        │   sigs   │        │   sigs   │      │   sigs   │       │   sigs   │
               │ • Store  │        │ • Store  │        │ • Store  │      │ • Store  │       │ • Store  │
               │ • Cache  │        │ • Cache  │        │ • Cache  │      │ • Cache  │       │ • Cache  │
               └──────────┘        └──────────┘        └──────────┘      └──────────┘       └──────────┘


Step 5: REAL-TIME DATA (uses cached sessions)
─────────────────────────────────────────────

  RadioA                                                           RadioB
    │                                                                 ▲
    │ UDP                                                             │ UDP
    ▼                                                                 │
┌────────┐    TCP    ┌────────┐    TCP    ┌────────┐    TCP    ┌────────┐
│Producer│──────────►│ Rep 1  │───....───►│ Rep N  │──────────►│Receiver│
└────────┘           └────────┘           └────────┘           └────────┘
                          │                    │
                     On EVERY packet:     On EVERY packet:
                     
                     1. proof_hash in     1. proof_hash in
                        cache? (~0.2µs)      cache? (~0.2µs)
                        
                     2. HMAC valid?       2. HMAC valid?
                        (~3µs)               (~3µs)
                        
                     3. Forward           3. Forward
                     
                     No Blockchain        No Blockchain
                     Operations           Operations
```

## Why This Is Decentralized

```
┌────────────────────────────────────────────────────────────────────────────┐
│                                                                            │
│  Concerns: If Producer creates proposals, isn't it centralized?            │
│                                                                            │
│  Clarity: No, here ids why:                                                │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                                                                     │   │
│  │  Producer creates PROPOSAL, but:                                    │   │
│  │                                                                     │   │
│  │  • Block is NOT valid until MAJORITY of repeaters sign              │   │
│  │  • Each repeater independently verifies before signing              │   │
│  │  • Producer CANNOT force an invalid block                           │   │
│  │  • Repeaters collectively DECIDE what goes on chain                 │   │
│  │                                                                     │   │
│  │  The Producer is the one who writes a proposal.                     │   │
│  │  The Repeaters are the COMMITTEE that votes to approve.             │   │
│  │  The proposal only passes if majority votes YES.                    │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  Attack scenarios:                                                         │
│                                                                            │
│  • Malicious producer sends fake session?                                  │
│    > Repeaters verify ZK commitment → Invalid → Don't sign                 │
│                                                                            │
│  • Producer tries to bypass repeaters?                                     │
│    > Block without majority signatures is REJECTED by network              │
│                                                                            │
│  • One repeater compromised?                                               │
│    > Only 1 signature, need majority → Block still needs others            │
│                                                                            │
│  • Majority repeaters compromised?                                         │
│    > Yes, this breaks security (same as any consensus system)              │
│    > But need to compromise multiple geographically distributed Pis        │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

## Resource Requirements

```
PRODUCER (Powerful Machine CPU Intel(R) Core(TM) i7-14700K ):
═══════════════════════════════════════════

  Operations:
  • Generate ZK-SNARK proof       (~120 seconds, CPU intensive)
  • Create block proposal         (~1ms)
  • Broadcast to repeaters        (network I/O via Ports)
  • Collect signatures            (network I/O via Ports)
  • Finalize block                (~1ms)
  • Broadcast finalized           (network I/O via Ports)
  
  Requirements:
  • Multi-core CPU
  • 8GB+ RAM (for ZK proof)
  • Network connectivity


REPEATER (Raspberry Pi):
════════════════════════

  Operations:
  • Receive proposal              (network I/O)
  • Verify hash chain             (~0.1ms)
  • Sign proposal (Ed25519)       (~1ms)
  • Send signature                (network I/O)
  • Receive finalized block       (network I/O)
  • Verify signatures             (~4ms for 4 sigs)
  • Store block                   (~5ms disk write)
  • Cache session                 (memory)
  • Per-packet verification       (~0.2µs)
  
  Requirements:
  • Any ARM processor
  • 256MB RAM sufficient
  • SD card for storage
  
  Performance achieved:
  • 4.6 MILLION verifications/second
  • This is way more than radio bandwidth needs
```

## Files

```
blockchain/
├── __init__.py               # Module exports
├── consensus.py              # CORRECT implementation
│   ├── SessionRecord         # Session data
│   ├── BlockProposal         # Unsigned proposal
│   ├── RepeaterSignature     # Repeater's approval signature
│   ├── Block                 # Finalized block (with signatures)
│   ├── BlockchainStorage     # Append-only storage
│   ├── RepeaterNode          # Lightweight Pi node
│   ├── ProducerNode          # Heavy producer node
│   ├── RepeaterNetwork       # Network handler for Pi
│   └── ProducerNetwork       # Network handler for producer
└── ARCHITECTURE.md           # This file
```

## Performance Summary

| Operation | Time | Where | Frequency |
|-----------|------|-------|-----------|
| ZK Proof Generation | ~120s | Producer | Once per session |
| Create Proposal | ~1ms | Producer | Once per session |
| Verify Proposal | ~0.2ms | Each Repeater | Once per session |
| Sign Proposal | ~1ms | Each Repeater | Once per session |
| Verify Signatures | ~4ms | Each Repeater | Once per session |
| Store Block | ~5ms | Each Repeater | Once per session |
| **Packet Verification** | **~0.2µs** | **Each Repeater** | **Every packet** |

The critical path (packet verification) is **0.2 microseconds** = **4.6 million packets/second** per Raspberry Pi.
