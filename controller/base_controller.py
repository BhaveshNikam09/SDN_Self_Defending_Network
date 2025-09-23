# intelligent_controller.py
import atexit
import time
from collections import defaultdict

import joblib
import pandas as pd
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, icmp, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3


class IntelligentController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IntelligentController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        
        # --- LOAD THE TRAINED MODEL ---
        try:
            self.model = joblib.load('intelligent_ddos_model.joblib')
            self.logger.info("Successfully loaded ML model 'intelligent_ddos_model.joblib'.")
        except FileNotFoundError:
            self.logger.error("Could not load model. Make sure 'intelligent_ddos_model.joblib' is in the same directory.")
            self.model = None

        # --- MODIFIED: Using a dictionary to store {ip: attack_type} ---
        self.blocked_attackers = {}
        
        # Data structures for real-time analysis
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0, 'byte_count': 0, 'syn_count': 0, 'fin_count': 0,
            'rst_count': 0, 'ack_count': 0, 'icmp_count': 0, 'start_time': time.time()
        })
        self.prediction_interval = 5  # seconds

        # Start the thread to periodically make predictions
        self.prediction_thread = hub.spawn(self._predict_and_mitigate)
        
        # Register the shutdown handler
        atexit.register(self._shutdown_handler)
        self.logger.info("Intelligent Controller Started. Defenses are active.")
    
    def _shutdown_handler(self):
        """Prints a detailed summary when the controller is stopped."""
        self.logger.info("Controller is shutting down. Generating attack summary...")
        num_attackers = len(self.blocked_attackers)
        
        # --- MODIFIED: New, more detailed summary report ---
        print("\n-----------------------------------------")
        print("          ATTACK SUMMARY           ")
        print("-----------------------------------------")
        print(f"Total Unique Attackers Detected: {num_attackers}")
        
        if num_attackers > 0:
            print("\nBlocked IP Addresses:")
            # Sort by IP address for a clean report
            for ip, attack_type in sorted(self.blocked_attackers.items()):
                print(f"  - {ip} (Detected as: {attack_type})")
        else:
            print("\nNo attackers were detected during this session.")
        
        print("-----------------------------------------")

    def _predict_and_mitigate(self):
        """Periodically uses the ML model to predict and block attacks."""
        while self.model:
            hub.sleep(self.prediction_interval)
            if not self.datapaths:
                continue

            flows_to_analyze = list(self.flow_stats.items())
            self.flow_stats.clear()

            if not flows_to_analyze:
                continue

            df_list = []
            flow_keys = []
            for src_ip, stats in flows_to_analyze:
                duration = time.time() - stats['start_time']
                if duration == 0: duration = self.prediction_interval
                
                df_list.append({
                    'packet_count': stats['packet_count'], 'byte_count': stats['byte_count'],
                    'syn_count': stats['syn_count'], 'fin_count': stats['fin_count'],
                    'rst_count': stats['rst_count'], 'ack_count': stats['ack_count'],
                    'icmp_count': stats['icmp_count'], 'duration_sec': duration
                })
                flow_keys.append(src_ip)
            
            features_df = pd.DataFrame(df_list, columns=[
                'packet_count', 'byte_count', 'syn_count', 'fin_count', 'rst_count', 
                'ack_count', 'icmp_count', 'duration_sec'
            ])
            
            predictions = self.model.predict(features_df)

            for source_ip, prediction in zip(flow_keys, predictions):
                # --- MODIFIED: Uses the new dictionary to store attack type ---
                if prediction != 0 and source_ip not in self.blocked_attackers:  # 0 is Benign
                    attack_type = "SYN Flood" if prediction == 1 else "ICMP Flood"
                    self.logger.warning(f"{attack_type} Detected from IP: {source_ip}!")
                    self.logger.warning("Deploying mitigation: Blocking all traffic from this IP.")
                    self.blocked_attackers[source_ip] = attack_type # Store the IP and attack type
                    
                    for datapath in self.datapaths.values():
                        self._add_block_rule(datapath, source_ip)

    def _add_block_rule(self, datapath, ip_src):
        """Installs a high-priority flow rule to drop packets."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = []
        inst = [parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=100,
            match=match,
            instructions=inst,
            hard_timeout=60
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=[
                                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)])
        datapath.send_msg(mod)
        self.logger.info("Switch %d connected.", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype == 0x88cc:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            flow_key = src_ip

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(msg.data)
            
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                if tcp_pkt.bits & 0b000010: stats['syn_count'] += 1
                if tcp_pkt.bits & 0b000001: stats['fin_count'] += 1
                if tcp_pkt.bits & 0b000100: stats['rst_count'] += 1
                if tcp_pkt.bits & 0b010000: stats['ack_count'] += 1

            if pkt.get_protocol(icmp.icmp):
                stats['icmp_count'] += 1
        
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(eth.dst, datapath.ofproto.OFPP_FLOOD)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)