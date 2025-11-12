# detection/attack_detection.py

import time
import joblib
import pandas as pd
from ryu.lib import hub

class AttackDetector:
    """A class that uses a trained ML model to detect DDoS attacks."""

    def __init__(self, config, logger, traffic_monitor, main_controller):
        self.logger = logger
        self.traffic_monitor = traffic_monitor
        self.main_controller = main_controller
        self.model = self._load_model(config['model_path'])
        
        self.prediction_interval = config['prediction_interval']
        self.blocked_attackers = {}  # {ip: attack_type}
        
        # Track victim information for better blocking
        self.attack_records = []  # List of {attacker, victim, attack_type, timestamp}
        
        # Track legitimate victims to prevent false positives
        self.known_victims = set()  # IPs that are being attacked (should not be blocked)

        # Start the background thread for making predictions
        if self.model:
            self.prediction_thread = hub.spawn(self._predict_and_mitigate)

    def _load_model(self, model_path):
        """Loads the trained machine learning model from a file."""
        try:
            model = joblib.load(model_path)
            self.logger.info(f"Successfully loaded ML model from '{model_path}'.")
            return model
        except FileNotFoundError:
            self.logger.error(f"Could not load model. Make sure '{model_path}' exists.")
            return None

    def _predict_and_mitigate(self):
        """Periodically runs predictions and triggers mitigation."""
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
                
                df_list.append({
                    'packet_count': stats['packet_count'], 
                    'byte_count': stats['byte_count'],
                    'syn_count': stats['syn_count'], 
                    'fin_count': stats['fin_count'],
                    'rst_count': stats['rst_count'], 
                    'ack_count': stats['ack_count'],
                    'icmp_count': stats['icmp_count'], 
                    'duration_sec': duration
                })
                flow_keys.append(flow_tuple)
            
            features_df = pd.DataFrame(df_list, columns=[
                'packet_count', 'byte_count', 'syn_count', 'fin_count', 
                'rst_count', 'ack_count', 'icmp_count', 'duration_sec'
            ])
            
            predictions = self.model.predict(features_df)

            for flow_tuple, prediction in zip(flow_keys, predictions):
                # flow_tuple is (source_ip, dest_ip)
                source_ip = flow_tuple[0]
                dest_ip = flow_tuple[1]
                
                # --- KEY FIX: Skip if source is already a known victim ---
                if source_ip in self.known_victims:
                    self.logger.debug(f"Skipping {source_ip} → {dest_ip} (source is a known victim)")
                    continue
                
                # --- KEY FIX: Skip if source is already blocked ---
                if source_ip in self.blocked_attackers:
                    self.logger.debug(f"Skipping {source_ip} → {dest_ip} (already blocked)")
                    continue
                
                if prediction != 0:
                    attack_type = "SYN Flood" if prediction == 1 else "ICMP Flood"
                    
                    # Log the attack with victim information
                    self.logger.warning(
                        f"🚨 {attack_type} Detected!\n"
                        f"   Attacker IP: {source_ip}\n"
                        f"   Victim IP: {dest_ip}"
                    )
                    
                    # Mark the destination as a known victim (should NOT be blocked)
                    self.known_victims.add(dest_ip)
                    
                    # Record this attack
                    self.blocked_attackers[source_ip] = attack_type
                    self.attack_records.append({
                        'attacker': source_ip,
                        'victim': dest_ip,
                        'attack_type': attack_type,
                        'timestamp': time.time()
                    })
                    
                    # Block the attacker with victim information
                    # This ensures only the attacker is blocked, not the victim
                    self.main_controller.block_attacker(
                        attacker_ip=source_ip,
                        victim_ip=dest_ip
                    )
                    
                    self.logger.info(f"✓ Mitigation deployed: {source_ip} blocked")
                    self.logger.info(f"✓ {dest_ip} marked as victim (will not be blocked)")

    def get_attack_summary(self):
        """Returns a summary of detected attacks."""
        summary = {
            'total_attackers': len(self.blocked_attackers),
            'blocked_ips': dict(self.blocked_attackers),
            'attack_records': self.attack_records,
            'known_victims': list(self.known_victims)
        }
        return summary

    def get_top_victims(self, top_n=5):
        """Returns the most targeted victim IPs."""
        if not self.attack_records:
            return []
        
        victim_counts = {}
        for record in self.attack_records:
            victim = record['victim']
            victim_counts[victim] = victim_counts.get(victim, 0) + 1
        
        # Sort by count descending
        sorted_victims = sorted(victim_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_victims[:top_n]

    def get_attacks_by_type(self):
        """Returns attack statistics grouped by type."""
        attack_type_counts = {}
        for attack_type in self.blocked_attackers.values():
            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
        return attack_type_counts