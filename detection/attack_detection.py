# detection/attack_detection.py
"""Enhanced Attack Detection - 6 Attack Types with False Positive Prevention"""

import time
import joblib
import pandas as pd
from ryu.lib import hub

class AttackDetector:
    """Detects multiple types of DDoS attacks using ML model."""
    
    # ========== ATTACK TYPE MAPPING ==========
    ATTACK_TYPES = {
        0: "Normal",
        1: "SYN Flood",
        2: "ICMP Flood",
        3: "UDP Flood",
        4: "ACK Flood",
        5: "RST Flood",
        6: "HTTP Flood"
    }
    # =========================================
    
    # ========== THRESHOLDS TO PREVENT FALSE POSITIVES ==========
    MIN_PACKET_COUNT = 500      # Minimum packets to be considered attack
    MIN_PACKET_RATE = 80        # Minimum packets/second
    # ===========================================================

    def __init__(self, config, logger, traffic_monitor, main_controller):
        self.logger = logger
        self.traffic_monitor = traffic_monitor
        self.main_controller = main_controller
        self.model = self._load_model(config['model_path'])
        
        self.prediction_interval = config['prediction_interval']
        self.blocked_attackers = {}
        self.attack_records = []
        self.known_victims = set()

        if self.model:
            self.prediction_thread = hub.spawn(self._predict_and_mitigate)

    def _load_model(self, model_path):
        """Loads the trained ML model"""
        try:
            model = joblib.load(model_path)
            self.logger.info(f"Successfully loaded ML model from '{model_path}'.")
            return model
        except FileNotFoundError:
            self.logger.error(f"Could not load model '{model_path}'.")
            return None

    def _is_legitimate_traffic(self, stats, duration):
        """
        Check if traffic is legitimate (not an attack).
        Prevents false positives from pingall and normal traffic bursts.
        
        Returns:
            True if traffic is legitimate (should NOT be analyzed)
            False if traffic is suspicious (should be analyzed)
        """
        packet_count = stats['packet_count']
        
        # Rule 1: Too few packets to be an attack
        if packet_count < self.MIN_PACKET_COUNT:
            return True
        
        # Rule 2: Packet rate too low
        if duration > 0:
            packet_rate = packet_count / duration
            if packet_rate < self.MIN_PACKET_RATE:
                return True
        
        # Rule 3: Very short flows (< 2 seconds) are usually normal
        if duration < 2:
            return True
        
        # Rule 4: Normal TCP handshake pattern detected
        syn_count = stats.get('syn_count', 0)
        ack_count = stats.get('ack_count', 0)
        
        if syn_count > 0 and ack_count > 0:
            # Normal traffic has balanced SYN/ACK ratio
            syn_ack_ratio = syn_count / (ack_count + 1)
            if 0.1 < syn_ack_ratio < 0.5 and packet_count < 1000:
                return True
        
        return False

    def _predict_and_mitigate(self):
        """Periodically runs predictions and triggers mitigation"""
        while True:
            hub.sleep(self.prediction_interval)
            
            flows_to_analyze = list(self.traffic_monitor.get_and_clear_stats().items())
            if not flows_to_analyze:
                continue

            df_list, flow_keys = [], []
            for flow_tuple, stats in flows_to_analyze:
                duration = time.time() - stats['start_time']
                if duration == 0: 
                    duration = self.prediction_interval
                
                # ===== CRITICAL FIX: Filter out legitimate traffic =====
                # This prevents pingall and normal bursts from being flagged
                if self._is_legitimate_traffic(stats, duration):
                    self.logger.debug(
                        f"Skipping legitimate traffic: {flow_tuple[0]} -> {flow_tuple[1]} "
                        f"({stats['packet_count']} packets in {duration:.1f}s)"
                    )
                    continue
                # ======================================================
                
                df_list.append({
                    'packet_count': stats['packet_count'], 
                    'byte_count': stats['byte_count'],
                    'syn_count': stats['syn_count'], 
                    'fin_count': stats['fin_count'],
                    'rst_count': stats['rst_count'], 
                    'ack_count': stats['ack_count'],
                    'icmp_count': stats['icmp_count'],
                    'udp_count': stats.get('udp_count', 0),
                    'duration_sec': duration
                })
                flow_keys.append(flow_tuple)
            
            # If no flows to analyze after filtering, continue
            if not df_list:
                continue
            
            features_df = pd.DataFrame(df_list, columns=[
                'packet_count', 'byte_count', 'syn_count', 'fin_count', 
                'rst_count', 'ack_count', 'icmp_count', 'udp_count', 'duration_sec'
            ])
            
            predictions = self.model.predict(features_df)

            for flow_tuple, prediction in zip(flow_keys, predictions):
                source_ip = flow_tuple[0]
                dest_ip = flow_tuple[1]
                
                # Skip if source is a known victim
                if source_ip in self.known_victims:
                    self.logger.debug(f"Skipping {source_ip} (known victim)")
                    continue
                
                # Skip if already blocked
                if source_ip in self.blocked_attackers:
                    continue
                
                # Only act on attacks (prediction != 0)
                if prediction != 0:
                    attack_type = self.ATTACK_TYPES.get(prediction, f"Unknown ({prediction})")
                    
                    self.logger.warning(
                        f"🚨 {attack_type} Detected!\n"
                        f"   Attacker IP: {source_ip}\n"
                        f"   Victim IP: {dest_ip}\n"
                        f"   Prediction Code: {prediction}"
                    )
                    
                    # Mark victim as protected
                    self.known_victims.add(dest_ip)
                    
                    # Record attack
                    self.blocked_attackers[source_ip] = attack_type
                    self.attack_records.append({
                        'attacker': source_ip,
                        'victim': dest_ip,
                        'attack_type': attack_type,
                        'timestamp': time.time()
                    })
                    
                    # Block attacker
                    self.main_controller.block_attacker(
                        attacker_ip=source_ip,
                        victim_ip=dest_ip
                    )
                    
                    self.logger.info(f"✓ {source_ip} blocked for {attack_type}")
                    self.logger.info(f"✓ {dest_ip} marked as victim (protected)")

    def get_attack_summary(self):
        """Returns attack summary"""
        return {
            'total_attackers': len(self.blocked_attackers),
            'blocked_ips': dict(self.blocked_attackers),
            'attack_records': self.attack_records,
            'known_victims': list(self.known_victims)
        }

    def get_top_victims(self, top_n=5):
        """Returns most targeted victims"""
        if not self.attack_records:
            return []
        
        victim_counts = {}
        for record in self.attack_records:
            victim = record['victim']
            victim_counts[victim] = victim_counts.get(victim, 0) + 1
        
        sorted_victims = sorted(victim_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_victims[:top_n]

    def get_attacks_by_type(self):
        """Returns attack statistics by type"""
        attack_type_counts = {}
        for attack_type in self.blocked_attackers.values():
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        return attack_type_counts