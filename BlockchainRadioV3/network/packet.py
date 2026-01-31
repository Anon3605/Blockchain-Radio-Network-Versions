"""
Packet structure for Radio Mesh Network with ZK-Proofs
Format: uid | sid | rid | data | zk-proof
"""

import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Optional
from queue import Queue


@dataclass
class Packet:
    """Radio mesh network packet structure"""
    uid: int
    sid: int
    rid: int
    data: str
    data_hash: str
    timestamp: float
    zk_proof: Optional[str] = None
    signature: Optional[str] = None
    hop_count: int = 0
    
    @staticmethod
    def create(uid: int, sid: int, data: str) -> 'Packet':
        """Create a new packet with computed hash"""
        data_hash = hashlib.sha256(data.encode()).hexdigest()
        return Packet(
            uid=uid,
            sid=sid,
            rid=0,
            data=data,
            data_hash=data_hash,
            timestamp=time.time(),
            hop_count=0
        )
    
    def verify_integrity(self) -> bool:
        """Verify that data hasn't been tampered with"""
        computed_hash = hashlib.sha256(self.data.encode()).hexdigest()
        return computed_hash == self.data_hash
    
    def update_repeater(self, new_rid: int):
        """Update repeater ID as packet hops through network"""
        self.rid = new_rid
        self.hop_count += 1
    
    def to_json(self) -> str:
        """Serialize packet to JSON"""
        return json.dumps(asdict(self))
    
    def to_bytes(self) -> bytes:
        """Serialize packet to bytes for transmission"""
        return self.to_json().encode('utf-8')
    
    @staticmethod
    def from_json(json_str: str) -> 'Packet':
        """Deserialize packet from JSON"""
        data = json.loads(json_str)
        return Packet(**data)
    
    @staticmethod
    def from_bytes(data: bytes) -> 'Packet':
        """Deserialize packet from bytes"""
        return Packet.from_json(data.decode('utf-8'))
    
    def get_size(self) -> int:
        """Get packet size in bytes"""
        return len(self.to_bytes())
    
    def __str__(self) -> str:
        return f"Packet(uid={self.uid}, sid={self.sid}, rid={self.rid}, hops={self.hop_count}, size={self.get_size()}B)"


class PacketQueue:
    """Thread-safe packet queue for buffering"""
    def __init__(self, maxsize: int = 100):
        self.queue = Queue(maxsize=maxsize)
        self.seen_uids = set()
    
    def add(self, packet: Packet) -> bool:
        """Add packet to queue if not seen before"""
        if packet.uid in self.seen_uids:
            return False
        
        self.seen_uids.add(packet.uid)
        self.queue.put(packet)
        return True
    
    def get(self, timeout: float = 1.0) -> Optional[Packet]:
        """Get next packet from queue"""
        try:
            return self.queue.get(timeout=timeout)
        except:
            return None
    
    def is_empty(self) -> bool:
        return self.queue.empty()
    
    def size(self) -> int:
        return self.queue.qsize()


class PacketStatistics:
    """Track statistics for performance analysis"""
    def __init__(self):
        self.total_packets = 0
        self.verified_packets = 0
        self.dropped_packets = 0
        self.duplicate_packets = 0
        self.tampered_packets = 0
        self.latencies = []
        self.packet_sizes = []
        self.verification_times = []
    
    def record_verified(self, packet: Packet, verification_time: float):
        """Record successfully verified packet"""
        self.total_packets += 1
        self.verified_packets += 1
        self.verification_times.append(verification_time)
        self.packet_sizes.append(packet.get_size())
    
    def record_dropped(self, reason: str):
        """Record dropped packet"""
        self.total_packets += 1
        self.dropped_packets += 1
        if reason == "tampered":
            self.tampered_packets += 1
        elif reason == "duplicate":
            self.duplicate_packets += 1
    
    def record_latency(self, packet: Packet, end_time: float):
        """Record end-to-end latency"""
        latency = end_time - packet.timestamp
        self.latencies.append(latency)
    
    def get_summary(self) -> dict:
        """Get statistics summary for thesis"""
        return {
            "total_packets": self.total_packets,
            "verified_packets": self.verified_packets,
            "dropped_packets": self.dropped_packets,
            "duplicate_packets": self.duplicate_packets,
            "tampered_packets": self.tampered_packets,
            "success_rate": self.verified_packets / self.total_packets if self.total_packets > 0 else 0,
            "avg_verification_time": sum(self.verification_times) / len(self.verification_times) if self.verification_times else 0,
            "avg_packet_size": sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
            "avg_latency": sum(self.latencies) / len(self.latencies) if self.latencies else 0,
            "min_latency": min(self.latencies) if self.latencies else 0,
            "max_latency": max(self.latencies) if self.latencies else 0,
        }
    
    def print_summary(self):
        """Print formatted summary"""
        summary = self.get_summary()
        print("\n" + "="*50)
        print("PACKET STATISTICS SUMMARY")
        print("="*50)
        print(f"Total Packets:      {summary['total_packets']}")
        print(f"Verified:           {summary['verified_packets']}")
        print(f"Dropped:            {summary['dropped_packets']}")
        print(f"  - Duplicates:     {summary['duplicate_packets']}")
        print(f"  - Tampered:       {summary['tampered_packets']}")
        print(f"Success Rate:       {summary['success_rate']*100:.2f}%")
        print(f"Avg Verify Time:    {summary['avg_verification_time']*1000:.2f}ms")
        print(f"Avg Packet Size:    {summary['avg_packet_size']:.0f} bytes")
        print(f"Avg Latency:        {summary['avg_latency']*1000:.2f}ms")
        print(f"Min Latency:        {summary['min_latency']*1000:.2f}ms")
        print(f"Max Latency:        {summary['max_latency']*1000:.2f}ms")
        print("="*50 + "\n")