#!/usr/bin/env python3
"""
Real Traffic Data Collector for DDoS Detection
Collects actual traffic data from Mininet and saves it for training
"""

import csv
import time
import os
from datetime import datetime

class DataCollector:
    """Collects and labels traffic data for ML training"""
    
    def __init__(self, output_file='ddos_training_data.csv'):
        self.output_file = output_file
        self.collected_samples = []
        self.initialize_csv()
    
    def initialize_csv(self):
        """Create CSV file with headers if it doesn't exist"""
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'src_ip', 'dst_ip', 'packet_count', 'byte_count',
                    'syn_count', 'fin_count', 'rst_count', 'ack_count',
                    'icmp_count', 'udp_count', 'duration_sec', 'label', 'attack_type'
                ])
            print(f"✓ Created new data collection file: {self.output_file}")
        else:
            print(f"✓ Appending to existing file: {self.output_file}")
    
    def collect_flow_data(self, flow_tuple, stats, label, attack_type):
        """
        Collect data from a flow and save it
        
        Args:
            flow_tuple: (src_ip, dst_ip)
            stats: Dictionary with flow statistics
            label: 0=Normal, 1=SYN Flood, 2=ICMP Flood, 3=UDP Flood
            attack_type: Human-readable attack type
        """
        src_ip, dst_ip = flow_tuple
        duration = time.time() - stats['start_time']
        
        sample = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'packet_count': stats['packet_count'],
            'byte_count': stats['byte_count'],
            'syn_count': stats['syn_count'],
            'fin_count': stats['fin_count'],
            'rst_count': stats['rst_count'],
            'ack_count': stats['ack_count'],
            'icmp_count': stats['icmp_count'],
            'udp_count': stats.get('udp_count', 0),
            'duration_sec': duration,
            'label': label,
            'attack_type': attack_type
        }
        
        self.collected_samples.append(sample)
        
        # Write to CSV immediately to prevent data loss
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sample.keys())
            writer.writerow(sample)
        
        return sample
    
    def get_statistics(self):
        """Return collection statistics"""
        if not self.collected_samples:
            return "No data collected yet"
        
        label_counts = {}
        for sample in self.collected_samples:
            attack_type = sample['attack_type']
            label_counts[attack_type] = label_counts.get(attack_type, 0) + 1
        
        return {
            'total_samples': len(self.collected_samples),
            'by_type': label_counts
        }
    
    def print_summary(self):
        """Print collection summary"""
        stats = self.get_statistics()
        if isinstance(stats, str):
            print(stats)
            return
        
        print("\n" + "="*60)
        print("DATA COLLECTION SUMMARY")
        print("="*60)
        print(f"Total Samples Collected: {stats['total_samples']}")
        print("\nSamples by Attack Type:")
        for attack_type, count in stats['by_type'].items():
            print(f"  • {attack_type}: {count}")
        print(f"\nData saved to: {self.output_file}")
        print("="*60 + "\n")