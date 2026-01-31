"""
Packet Structure for Blockchain Radio V4

Supports two packet types:
1. SessionPacket: For handshake and session establishment (ZK-SNARK)
2. DataPacket: For real-time data with HMAC authentication

The key optimization is that DataPackets only carry HMAC tags (~32 bytes)
instead of full ZK proofs (~10KB), enabling real-time transmission.
"""

import json
import hashlib
import struct
import time
from dataclasses import dataclass, asdict, field
from typing import Optional, Union
from queue import Queue
from enum import Enum, auto


class PacketType(Enum):
    """Packet types in the protocol"""
    # Session establishment
    SESSION_HELLO = 1
    SESSION_CHALLENGE = 2
    SESSION_PROOF = 3
    SESSION_VERIFY = 4
    SESSION_CONFIRM = 5
    SESSION_CLOSE = 6
    
    # Real-time data (uses HMAC)
    DATA = 10
    DATA_ACK = 11
    
    # Control
    PING = 20
    PONG = 21
    ERROR = 255


@dataclass
class Packet:
    """Base packet structure"""
    packet_type: PacketType
    uid: int
    sid: int              # Source node ID
    rid: int              # Current repeater ID
    session_id: str       # Session identifier
    timestamp: float = field(default_factory=time.time)
    hop_count: int = 0
    
    def update_repeater(self, new_rid: int) -> None:
        """Update repeater ID as packet hops"""
        self.rid = new_rid
        self.hop_count += 1
    
    def get_header_bytes(self) -> bytes:
        """Get packet header as bytes"""
        session_bytes = self.session_id.encode('utf-8')
        return struct.pack(
            f'!BHIIH{len(session_bytes)}sdH',
            self.packet_type.value,
            len(session_bytes),
            self.uid,
            self.sid,
            self.rid,
            session_bytes,
            self.timestamp,
            self.hop_count
        )
    
    @staticmethod
    def parse_header(data: bytes) -> tuple['Packet', int]:
        """Parse packet header, return (packet, offset)"""
        packet_type = PacketType(struct.unpack('!B', data[0:1])[0])
        sid_len = struct.unpack('!H', data[1:3])[0]
        
        header_fmt = f'!BHIIH{sid_len}sdH'
        header_size = struct.calcsize(header_fmt)
        
        _, _, uid, sid, rid, session_bytes, timestamp, hop_count = struct.unpack(
            header_fmt, data[:header_size]
        )
        
        packet = Packet(
            packet_type=packet_type,
            uid=uid,
            sid=sid,
            rid=rid,
            session_id=session_bytes.decode('utf-8'),
            timestamp=timestamp,
            hop_count=hop_count
        )
        
        return packet, header_size


@dataclass
class SessionPacket(Packet):
    """
    Packet for session establishment
    
    Contains ZK proof data for handshake.
    Used only during session setup (~120s one-time cost).
    """
    handshake_data: bytes = b''
    
    def __post_init__(self):
        if self.packet_type not in (
            PacketType.SESSION_HELLO,
            PacketType.SESSION_CHALLENGE,
            PacketType.SESSION_PROOF,
            PacketType.SESSION_VERIFY,
            PacketType.SESSION_CONFIRM,
            PacketType.SESSION_CLOSE,
        ):
            raise ValueError(f"Invalid packet type for SessionPacket: {self.packet_type}")
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        header = self.get_header_bytes()
        payload = struct.pack(f'!I{len(self.handshake_data)}s',
                            len(self.handshake_data),
                            self.handshake_data)
        return header + payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SessionPacket':
        """Deserialize from bytes"""
        base, offset = Packet.parse_header(data)
        
        # Parse handshake data
        data_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        handshake_data = data[offset:offset+data_len]
        
        return cls(
            packet_type=base.packet_type,
            uid=base.uid,
            sid=base.sid,
            rid=base.rid,
            session_id=base.session_id,
            timestamp=base.timestamp,
            hop_count=base.hop_count,
            handshake_data=handshake_data
        )
    
    def get_size(self) -> int:
        """Get packet size in bytes"""
        return len(self.to_bytes())


@dataclass
class DataPacket(Packet):
    """
    Packet for real-time data transmission
    
    Uses HMAC authentication for fast verification (~0.1ms).
    
    CRITICAL: Contains proof_hash (32 bytes), NOT the full ZK proof (~10KB).
    The HMAC is computed over: proof_hash || session_id || seq || timestamp || data
    
    This means every message is cryptographically bound to the original ZK proof,
    but we only transmit 32 bytes instead of 10KB per message.
    """
    data: bytes = b''
    data_hash: str = ''
    
    # HMAC authentication (fast verification)
    hmac_tag: bytes = b''
    sequence: int = 0
    
    # THE KEY ADDITION: proof_hash binds this message to the ZK proof
    # This is SHA256(zk_proof) computed during session establishment
    proof_hash: bytes = b'\x00' * 32
    
    def __post_init__(self):
        if self.packet_type not in (PacketType.DATA, PacketType.DATA_ACK):
            raise ValueError(f"Invalid packet type for DataPacket: {self.packet_type}")
        
        # Compute hash if not set
        if not self.data_hash and self.data:
            self.data_hash = hashlib.sha256(self.data).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify data hasn't been tampered with (hash check)"""
        if not self.data:
            return True
        computed = hashlib.sha256(self.data).hexdigest()
        return computed == self.data_hash
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes"""
        header = self.get_header_bytes()
        hash_bytes = self.data_hash.encode('utf-8')
        
        # Include proof_hash in the packet!
        payload = struct.pack(
            f'!32sI{len(self.data)}s64sQ32s',
            self.proof_hash,              # 32 bytes - THE ZK BINDING
            len(self.data),
            self.data,
            hash_bytes.ljust(64, b'\x00'),
            self.sequence,
            self.hmac_tag.ljust(32, b'\x00')
        )
        return header + payload
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'DataPacket':
        """Deserialize from bytes"""
        base, offset = Packet.parse_header(data)
        
        # Parse proof_hash first
        proof_hash = data[offset:offset+32]
        offset += 32
        
        # Parse data payload
        data_len = struct.unpack('!I', data[offset:offset+4])[0]
        offset += 4
        payload = data[offset:offset+data_len]
        offset += data_len
        
        # Parse hash, sequence, hmac
        hash_bytes, sequence, hmac_tag = struct.unpack(
            '!64sQ32s', data[offset:offset+104]
        )
        
        return cls(
            packet_type=base.packet_type,
            uid=base.uid,
            sid=base.sid,
            rid=base.rid,
            session_id=base.session_id,
            timestamp=base.timestamp,
            hop_count=base.hop_count,
            data=payload,
            data_hash=hash_bytes.rstrip(b'\x00').decode('utf-8'),
            sequence=sequence,
            hmac_tag=hmac_tag.rstrip(b'\x00'),
            proof_hash=proof_hash
        )
    
    def get_size(self) -> int:
        """Get packet size in bytes"""
        return len(self.to_bytes())
    
    def __str__(self) -> str:
        return (f"DataPacket(uid={self.uid}, sid={self.sid}, rid={self.rid}, "
                f"seq={self.sequence}, hops={self.hop_count}, size={self.get_size()}B)")


def parse_packet(data: bytes) -> Union[SessionPacket, DataPacket, Packet]:
    """Parse packet from bytes, return appropriate type"""
    packet_type = PacketType(struct.unpack('!B', data[0:1])[0])
    
    if packet_type in (
        PacketType.SESSION_HELLO,
        PacketType.SESSION_CHALLENGE,
        PacketType.SESSION_PROOF,
        PacketType.SESSION_VERIFY,
        PacketType.SESSION_CONFIRM,
        PacketType.SESSION_CLOSE,
    ):
        return SessionPacket.from_bytes(data)
    elif packet_type in (PacketType.DATA, PacketType.DATA_ACK):
        return DataPacket.from_bytes(data)
    else:
        return Packet.parse_header(data)[0]


class PacketQueue:
    """Thread-safe packet queue with deduplication"""
    
    def __init__(self, maxsize: int = 1000):
        self.queue = Queue(maxsize=maxsize)
        self.seen_uids: set = set()
        self._max_seen = 10000  # Limit seen tracking
    
    def add(self, packet: Union[SessionPacket, DataPacket, Packet]) -> bool:
        """Add packet if not duplicate"""
        if packet.uid in self.seen_uids:
            return False
        
        self.seen_uids.add(packet.uid)
        self.queue.put(packet)
        
        # Cleanup old UIDs if too many
        if len(self.seen_uids) > self._max_seen:
            # Remove oldest half
            self.seen_uids = set(list(self.seen_uids)[self._max_seen // 2:])
        
        return True
    
    def get(self, timeout: float = 1.0) -> Optional[Union[SessionPacket, DataPacket, Packet]]:
        """Get next packet"""
        try:
            return self.queue.get(timeout=timeout)
        except:
            return None
    
    def is_empty(self) -> bool:
        return self.queue.empty()
    
    def size(self) -> int:
        return self.queue.qsize()


@dataclass
class PacketStatistics:
    """Track packet statistics for performance analysis"""
    
    total_packets: int = 0
    session_packets: int = 0
    data_packets: int = 0
    verified_packets: int = 0
    dropped_packets: int = 0
    duplicate_packets: int = 0
    tampered_packets: int = 0
    
    latencies: list = field(default_factory=list)
    verification_times: list = field(default_factory=list)
    packet_sizes: list = field(default_factory=list)
    
    def record_session_packet(self, packet: SessionPacket) -> None:
        """Record session packet"""
        self.total_packets += 1
        self.session_packets += 1
        self.packet_sizes.append(packet.get_size())
    
    def record_data_packet(self, packet: DataPacket, verification_time: float) -> None:
        """Record verified data packet"""
        self.total_packets += 1
        self.data_packets += 1
        self.verified_packets += 1
        self.verification_times.append(verification_time)
        self.packet_sizes.append(packet.get_size())
    
    def record_dropped(self, reason: str) -> None:
        """Record dropped packet"""
        self.total_packets += 1
        self.dropped_packets += 1
        if reason == "tampered":
            self.tampered_packets += 1
        elif reason == "duplicate":
            self.duplicate_packets += 1
    
    def record_latency(self, packet: DataPacket, end_time: float) -> None:
        """Record end-to-end latency"""
        latency = end_time - packet.timestamp
        self.latencies.append(latency)
    
    def get_summary(self) -> dict:
        """Get statistics summary"""
        return {
            "total_packets": self.total_packets,
            "session_packets": self.session_packets,
            "data_packets": self.data_packets,
            "verified_packets": self.verified_packets,
            "dropped_packets": self.dropped_packets,
            "duplicate_packets": self.duplicate_packets,
            "tampered_packets": self.tampered_packets,
            "success_rate": self.verified_packets / self.total_packets if self.total_packets > 0 else 0,
            "avg_verification_time_ms": (sum(self.verification_times) / len(self.verification_times) * 1000) if self.verification_times else 0,
            "avg_packet_size": sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
            "avg_latency_ms": (sum(self.latencies) / len(self.latencies) * 1000) if self.latencies else 0,
            "min_latency_ms": min(self.latencies) * 1000 if self.latencies else 0,
            "max_latency_ms": max(self.latencies) * 1000 if self.latencies else 0,
        }
    
    def print_summary(self) -> None:
        """Print formatted summary"""
        summary = self.get_summary()
        print("\n" + "=" * 60)
        print("PACKET STATISTICS SUMMARY")
        print("=" * 60)
        print(f"Total Packets:      {summary['total_packets']}")
        print(f"  Session:          {summary['session_packets']}")
        print(f"  Data:             {summary['data_packets']}")
        print(f"Verified:           {summary['verified_packets']}")
        print(f"Dropped:            {summary['dropped_packets']}")
        print(f"  - Duplicates:     {summary['duplicate_packets']}")
        print(f"  - Tampered:       {summary['tampered_packets']}")
        print(f"Success Rate:       {summary['success_rate']*100:.2f}%")
        print(f"Avg Verify Time:    {summary['avg_verification_time_ms']:.4f}ms")
        print(f"Avg Packet Size:    {summary['avg_packet_size']:.0f} bytes")
        print(f"Avg Latency:        {summary['avg_latency_ms']:.2f}ms")
        print(f"Min Latency:        {summary['min_latency_ms']:.2f}ms")
        print(f"Max Latency:        {summary['max_latency_ms']:.2f}ms")
        print("=" * 60 + "\n")


if __name__ == '__main__':
    import os
    
    print("Packet Structure Test")
    print("=" * 50)
    
    # Test SessionPacket
    print("\n1. SessionPacket:")
    session_pkt = SessionPacket(
        packet_type=PacketType.SESSION_PROOF,
        uid=1,
        sid=100,
        rid=0,
        session_id="test-session-123",
        handshake_data=b'{"proof": "test_proof_data"}'
    )
    
    serialized = session_pkt.to_bytes()
    print(f"   Size: {len(serialized)} bytes")
    
    restored = SessionPacket.from_bytes(serialized)
    print(f"   Restored: uid={restored.uid}, type={restored.packet_type.name}")
    
    # Test DataPacket
    print("\n2. DataPacket:")
    data_pkt = DataPacket(
        packet_type=PacketType.DATA,
        uid=2,
        sid=100,
        rid=1,
        session_id="test-session-123",
        data=b"Hello, Radio Network!" * 10,
        sequence=1,
        hmac_tag=os.urandom(32)
    )
    
    serialized = data_pkt.to_bytes()
    print(f"   Size: {len(serialized)} bytes")
    print(f"   Data size: {len(data_pkt.data)} bytes")
    
    restored = DataPacket.from_bytes(serialized)
    print(f"   Restored: uid={restored.uid}, seq={restored.sequence}")
    print(f"   Integrity: {restored.verify_integrity()}")
    
    # Test parse_packet
    print("\n3. Generic parsing:")
    for pkt in [session_pkt, data_pkt]:
        parsed = parse_packet(pkt.to_bytes())
        print(f"   Parsed: {type(parsed).__name__}, type={parsed.packet_type.name}")
    
    # Test statistics
    print("\n4. Statistics:")
    stats = PacketStatistics()
    
    for i in range(100):
        stats.record_data_packet(data_pkt, 0.0001)
    stats.record_dropped("duplicate")
    stats.record_dropped("tampered")
    
    summary = stats.get_summary()
    print(f"   Total: {summary['total_packets']}")
    print(f"   Success rate: {summary['success_rate']*100:.1f}%")
    print(f"   Avg verify time: {summary['avg_verification_time_ms']:.4f}ms")
    
    print()
    print("=" * 50)
    print("Packet test completed!")
