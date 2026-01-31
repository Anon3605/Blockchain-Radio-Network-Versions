"""
Network Module for Blockchain Radio V4

Implements the mesh network infrastructure:
- Producer: Receives from RadioA, generates ZK proofs, establishes sessions
- Repeater: Forwards packets with fast HMAC verification
- Receiver: Final verification and delivery to RadioB

All nodes support session-based authentication for real-time messaging.
"""

from .packet import (
    Packet, 
    PacketType, 
    SessionPacket, 
    DataPacket,
    PacketQueue, 
    PacketStatistics
)

__all__ = [
    'Packet',
    'PacketType',
    'SessionPacket',
    'DataPacket',
    'PacketQueue',
    'PacketStatistics',
]
