# traffic_monitor.py - detection module
# detection/traffic_monitor.py
"""
Traffic Monitor for SDN Self-Defending Network
Collects traffic statistics and helps detect suspicious behavior.
"""

from collections import defaultdict
import time
import logging
import os

# Setup logging to file
log_dir = os.path.join(os.path.dirname(__file__), "..", "logs")
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=os.path.join(log_dir, "traffic.log"),
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

class TrafficMonitor:
    def __init__(self):
        # Dictionary: {src_ip: packet_count}
        self.packet_counts = defaultdict(int)
        # Dictionary: {src_ip: syn_count}
        self.syn_counts = defaultdict(int)

    def log_packet(self, src_ip, dst_ip, proto=None, flags=None):
        """Log packet details and update counts."""
        self.packet_counts[src_ip] += 1
        logging.info(f"Packet {src_ip} -> {dst_ip}, proto={proto}, flags={flags}")

        # Detect SYN packets (for SYN flood monitoring)
        if proto == "TCP" and flags == "S":  # SYN flag only
            self.syn_counts[src_ip] += 1

    def detect_anomaly(self, threshold=50):
        """
        Check if any IP exceeds packet threshold.
        Returns list of suspicious IPs.
        """
        suspicious = []
        for ip, count in self.syn_counts.items():
            if count > threshold:
                suspicious.append(ip)
                logging.warning(f"🚨 Suspicious IP detected: {ip}, SYN count={count}")
        return suspicious

if __name__ == "__main__":
    monitor = TrafficMonitor()

    # Example usage (for testing only)
    for i in range(60):
        monitor.log_packet("10.0.0.100", "10.0.0.2", proto="TCP", flags="S")
    
    suspects = monitor.detect_anomaly(threshold=50)
    print("Suspicious IPs:", suspects)
