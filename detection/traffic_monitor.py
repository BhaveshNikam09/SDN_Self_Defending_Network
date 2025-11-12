# detection/traffic_monitor.py

import time
from collections import defaultdict
from ryu.lib.packet import icmp, tcp

class TrafficMonitor:
    """A class to monitor and collect traffic statistics for flow analysis."""
    
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0, 'byte_count': 0, 'syn_count': 0, 
            'fin_count': 0, 'rst_count': 0, 'ack_count': 0, 
            'icmp_count': 0, 'start_time': time.time()
        })
    
    def collect_stats(self, pkt, ip_pkt, msg_len):
        """
        Updates statistics for a given flow based on the incoming packet.
        """
        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        flow_key = (src_ip, dst_ip)
        
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += msg_len
        
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            if tcp_pkt.bits & 2: stats['syn_count'] += 1    # SYN
            if tcp_pkt.bits & 1: stats['fin_count'] += 1    # FIN
            if tcp_pkt.bits & 4: stats['rst_count'] += 1    # RST
            if tcp_pkt.bits & 16: stats['ack_count'] += 1   # ACK
            
        if pkt.get_protocol(icmp.icmp):
            stats['icmp_count'] += 1
            
    def get_and_clear_stats(self):
        """
        Returns the current statistics and clears the internal state.
        This is called periodically by the detection module.
        """
        current_stats = self.flow_stats
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0, 'byte_count': 0, 'syn_count': 0, 
            'fin_count': 0, 'rst_count': 0, 'ack_count': 0, 
            'icmp_count': 0, 'start_time': time.time()
        })
        return current_stats