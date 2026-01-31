"""
Blockchain Module for Blockchain Radio V4

CORRECT ARCHITECTURE: Producer Proposes, Repeaters Decide
=========================================================

The blockchain is RUN BY THE REPEATERS collectively.
Producer PROPOSES, Repeaters VERIFY and SIGN, Majority = CONSENSUS.

Flow:
  1. Producer creates block PROPOSAL
  2. Producer broadcasts to all repeaters
  3. Each repeater: Verify → Sign → Return signature
  4. Producer collects signatures
  5. When MAJORITY sign → Block is FINALIZED
  6. Producer broadcasts finalized block
  7. Repeaters store block + cache sessions

This is:
  • DECENTRALIZED: Repeaters decide by signing (majority consensus)
  • LIGHTWEIGHT: Repeaters only verify hash + sign (~1ms), not heavy computation
  • PI-FRIENDLY: Raspberry Pi can easily handle verify + sign + cache

Port Assignment:
  • 7xxx: Block proposals/signatures/finalized (TCP)
  • 5xxx: Data forwarding (TCP)
  • UDP: Radio endpoints

Resource Requirements:
  • Producer: Powerful (ZK proof generation, block creation)
  • Repeater: Raspberry Pi (verify, sign, cache, forward)
"""

from .consensus import (
    # Data structures
    SessionRecord,
    BlockProposal,
    RepeaterSignature,
    Block,
    
    # Storage
    BlockchainStorage,
    
    # Nodes
    RepeaterNode,
    ProducerNode,
    
    # Network
    ProducerNetwork,
    RepeaterNetwork,
    
    # Protocol
    MSG_PROPOSAL,
    MSG_SIGNATURE,
    MSG_FINALIZED,
    MSG_ACK,
    pack_message,
    unpack_message,
    
    # Convenience
    establish_session_full_flow,
)

__all__ = [
    # Data structures
    'SessionRecord',
    'BlockProposal',
    'RepeaterSignature',
    'Block',
    
    # Storage
    'BlockchainStorage',
    
    # Nodes
    'RepeaterNode',
    'ProducerNode',
    
    # Network
    'ProducerNetwork',
    'RepeaterNetwork',
    
    # Protocol
    'MSG_PROPOSAL',
    'MSG_SIGNATURE', 
    'MSG_FINALIZED',
    'MSG_ACK',
    'pack_message',
    'unpack_message',
    
    # Convenience
    'establish_session_full_flow',
]
