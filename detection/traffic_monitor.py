# detection/traffic_monitor.py
"""Enhanced Traffic Monitor with UDP support"""

import time
from ryu.lib.packet import packet, tcp, icmp, udp

class TrafficMonitor:
    """Traffic monitor that tracks TCP, ICMP, and UDP packets."""
    
    def __init__(self):
        self.flow_stats = {}  # {(src_ip, dst_ip): {stats}}

    def collect_stats(self, pkt, ip_pkt, packet_size):
        """
        Collects statistics for each flow.
        
        Args:
            pkt: The packet object
            ip_pkt: The IPv4 packet
            packet_size: Size of the packet in bytes
        """
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        flow_key = (src_ip, dst_ip)

        # Initialize flow stats if new
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'syn_count': 0,
                'fin_count': 0,
                'rst_count': 0,
                'ack_count': 0,
                'icmp_count': 0,
                'udp_count': 0,
                'start_time': time.time()
            }

        # Update basic counters
        self.flow_stats[flow_key]['packet_count'] += 1
        self.flow_stats[flow_key]['byte_count'] += packet_size

        # TCP packet analysis
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            if tcp_pkt.has_flags(tcp.TCP_SYN):
                self.flow_stats[flow_key]['syn_count'] += 1
            if tcp_pkt.has_flags(tcp.TCP_FIN):
                self.flow_stats[flow_key]['fin_count'] += 1
            if tcp_pkt.has_flags(tcp.TCP_RST):
                self.flow_stats[flow_key]['rst_count'] += 1
            if tcp_pkt.has_flags(tcp.TCP_ACK):
                self.flow_stats[flow_key]['ack_count'] += 1

        # ICMP packet analysis
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            self.flow_stats[flow_key]['icmp_count'] += 1

        # UDP packet analysis
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            self.flow_stats[flow_key]['udp_count'] += 1

    def get_and_clear_stats(self):
        """Returns current flow statistics and clears the buffer."""
        stats = self.flow_stats.copy()
        self.flow_stats.clear()
        return stats

    def get_flow_count(self):
        """Returns the number of active flows."""
        return len(self.flow_stats)

    def get_total_packets(self):
        """Returns the total number of packets across all flows."""
        return sum(stats['packet_count'] for stats in self.flow_stats.values())

    def get_total_bytes(self):
        """Returns the total number of bytes across all flows."""
        return sum(stats['byte_count'] for stats in self.flow_stats.values())