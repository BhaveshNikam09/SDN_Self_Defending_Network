# controller/base_controller.py
import sys
import os
import time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import atexit
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event

# --- Import the topology discovery library ---
from ryu.topology import switches

# --- FIXED: Import the correct REST API components ---
from ryu.app.wsgi import WSGIApplication

# --- Import our custom modules ---
from detection.traffic_monitor import TrafficMonitor
from detection.attack_detection import AttackDetector
from firewall.mitigation import MitigationManager
from visualization.visualizer import Visualizer 

class IntelligentController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    # --- FIXED: Only include necessary contexts ---
    _CONTEXTS = {
        'switches': switches.Switches,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(IntelligentController, self).__init__(*args, **kwargs)
        self.logger.info("--- Initializing Intelligent SDN Controller ---")

        self.mac_to_port = {}
        self.datapaths = {}

        # --- Initialize WSGI (REST API will be available through ofctl_rest app) ---
        wsgi = kwargs['wsgi']
        self.logger.info("WSGI application initialized")

        # ========== CONFIG (LINE 49-52) ==========
        config = {
            'model_path': 'intelligent_ddos_model_6attacks.joblib',  # ← CHANGE THIS
            'prediction_interval': 5
        }
        # =========================================

        self.monitor = TrafficMonitor()
        self.mitigator = MitigationManager(self.logger)
        
        # Create detector first (without visualizer reference)
        self.detector = AttackDetector(config, self.logger, self.monitor, self)
        
        # Create visualizer with detector reference
        self.visualizer = Visualizer(self.logger, self.monitor, self.detector)
        
        atexit.register(self._shutdown_handler)

    def _shutdown_handler(self):
        self.logger.info("Controller is shutting down. Generating attack summary...")
        
        summary = self.detector.get_attack_summary()
        attack_types = self.detector.get_attacks_by_type()
        top_victims = self.detector.get_top_victims(top_n=5)
        
        print("\n" + "="*60)
        print("                  FINAL ATTACK SUMMARY                    ")
        print("="*60)
        print(f"Total Unique Attackers Blocked: {summary['total_attackers']}")
        print(f"Total Legitimate Victims Protected: {len(summary.get('known_victims', []))}")
        
        if summary['total_attackers'] > 0:
            print("\n" + "-"*60)
            print("BLOCKED ATTACKERS:")
            print("-"*60)
            for ip, attack_type in sorted(summary['blocked_ips'].items()):
                print(f"  🚫 {ip:15s} → {attack_type}")
            
            if summary.get('known_victims'):
                print("\n" + "-"*60)
                print("PROTECTED VICTIMS (NOT BLOCKED):")
                print("-"*60)
                for victim_ip in sorted(summary['known_victims']):
                    print(f"  🛡️  {victim_ip:15s} (Protected)")
            
            print("\n" + "-"*60)
            print("ATTACK TYPES:")
            print("-"*60)
            for attack_type, count in attack_types.items():
                print(f"  • {attack_type}: {count} attacker(s)")
            
            if top_victims:
                print("\n" + "-"*60)
                print("MOST TARGETED VICTIMS:")
                print("-"*60)
                for i, (victim_ip, attack_count) in enumerate(top_victims, 1):
                    print(f"  {i}. {victim_ip} - attacked {attack_count} time(s)")
            
            print("\n" + "-"*60)
            print("DETAILED ATTACK LOG:")
            print("-"*60)
            for i, record in enumerate(summary['attack_records'], 1):
                timestamp = time.strftime('%H:%M:%S', time.localtime(record['timestamp']))
                print(f"  [{i}] {timestamp} - {record['attack_type']}")
                print(f"      Attacker: {record['attacker']} → Victim: {record['victim']}")
        else:
            print("\n✓ No attacks were detected during this session.")
        
        print("="*60 + "\n")
    
    def block_attacker(self, attacker_ip, victim_ip=None):
        """
        Blocks an attacker's IP address.
        
        Args:
            attacker_ip (str): The IP address of the attacker to block
            victim_ip (str, optional): The IP address of the victim being attacked
        """
        self.logger.warning(f"Blocking attacker: {attacker_ip}")
        if victim_ip:
            self.logger.info(f"Victim IP: {victim_ip}")
        
        # Block the attacker with optional victim info
        self.mitigator.block_ip_address(self.datapaths, attacker_ip, victim_ip)
        
        # Update visualization to show attacker as blocked
        self.visualizer.update_node_status(attacker_ip, 'blocked')

    # The topology events are now automatically sent to this app
    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        self.visualizer.handle_switch_enter(ev)

    @set_ev_cls(event.EventLinkAdd)
    def handler_link_add(self, ev):
        self.visualizer.handle_link_add(ev)

    @set_ev_cls(event.EventHostAdd)
    def handler_host_add(self, ev):
        self.visualizer.handle_host_add(ev)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto, parser = datapath.ofproto, datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg, datapath, in_port = ev.msg, ev.msg.datapath, ev.msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if not eth or eth.ethertype == 0x88cc: return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.monitor.collect_stats(pkt, ip_pkt, len(msg.data))

        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(eth.dst, datapath.ofproto.OFPP_FLOOD)
        
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)