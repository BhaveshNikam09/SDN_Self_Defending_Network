# controller/data_collection_controller.py
"""
DATA COLLECTION CONTROLLER - 6 Attack Types
Access web interface at: http://localhost:5001
"""

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

from flask import Flask, render_template_string, request, jsonify

from detection.traffic_monitor import TrafficMonitor

import csv
import time
from datetime import datetime

class DataCollectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DataCollectionController, self).__init__(*args, **kwargs)
        
        self.logger.info("="*70)
        self.logger.info("  DATA COLLECTION MODE - 6 ATTACK TYPES")
        self.logger.info("="*70)
        
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor = TrafficMonitor()
        
        self.output_file = 'ddos_training_data_6attacks.csv'
        self.collection_interval = 5
        self.current_label = 0
        self.current_attack_type = "Normal"
        
        self.total_samples = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0, '5': 0, '6': 0}
        
        self._initialize_csv()
        
        self.app = Flask(__name__)
        self._setup_web_routes()
        self.web_thread = hub.spawn(self._run_web_server)
        
        self.collection_thread = hub.spawn(self._collect_data_periodically)
        
        self.logger.info(f"✓ Data file: {self.output_file}")
        self.logger.info("✓ Web interface: http://localhost:5001")
        self.logger.info(f"✓ Current label: {self.current_label} ({self.current_attack_type})")

    def _initialize_csv(self):
        """Create CSV file with headers"""
        if not os.path.exists(self.output_file):
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'src_ip', 'dst_ip', 'packet_count', 'byte_count',
                    'syn_count', 'fin_count', 'rst_count', 'ack_count',
                    'icmp_count', 'udp_count', 'duration_sec', 'label', 'attack_type'
                ])
            self.logger.info(f"✓ Created new data file")

    def _setup_web_routes(self):
        """Setup Flask routes for web interface"""
        @self.app.route('/')
        def index():
            return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Data Collection Control - 6 Attacks</title>
    <style>
        body { font-family: Arial; max-width: 1000px; margin: 50px auto; padding: 20px; }
        h1 { color: #333; text-align: center; }
        .label-button { 
            padding: 15px 30px; margin: 10px; font-size: 16px; 
            cursor: pointer; border: none; border-radius: 5px; color: white;
            display: inline-block; min-width: 200px;
        }
        .label-0 { background: #4CAF50; }
        .label-1 { background: #f44336; }
        .label-2 { background: #FF9800; }
        .label-3 { background: #2196F3; }
        .label-4 { background: #9C27B0; }
        .label-5 { background: #E91E63; }
        .label-6 { background: #00BCD4; }
        .current { 
            border: 5px solid gold; font-weight: bold; 
            transform: scale(1.05); box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        .stats { 
            margin: 20px 0; padding: 20px; background: #f5f5f5; 
            border-radius: 5px; font-size: 14px;
        }
        .instruction { 
            margin: 20px 0; padding: 15px; background: #e3f2fd; 
            border-left: 5px solid #2196F3; border-radius: 3px;
        }
        .command { 
            background: #263238; color: #4CAF50; padding: 8px; 
            border-radius: 3px; font-family: monospace; margin: 3px 0;
            font-size: 13px;
        }
        .button-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .progress-bar {
            width: 100%;
            background: #e0e0e0;
            border-radius: 5px;
            overflow: hidden;
            margin: 5px 0;
        }
        .progress-fill {
            height: 20px;
            background: #4CAF50;
            text-align: center;
            color: white;
            font-size: 12px;
            line-height: 20px;
        }
    </style>
</head>
<body>
    <h1>🎯 Data Collection Control Panel - 6 Attack Types</h1>
    
    <div class="stats">
        <h2>Current Status</h2>
        <p><strong>Current Label:</strong> <span id="current-label">Loading...</span></p>
        <p><strong>Samples Collected (Target: 150+ each):</strong></p>
        <div>
            <div>Label 0 (Normal): <span id="count-0">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-0" style="width: 0%">0%</div></div>
            </div>
            <div>Label 1 (SYN Flood): <span id="count-1">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-1" style="width: 0%">0%</div></div>
            </div>
            <div>Label 2 (ICMP Flood): <span id="count-2">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-2" style="width: 0%">0%</div></div>
            </div>
            <div>Label 3 (UDP Flood): <span id="count-3">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-3" style="width: 0%">0%</div></div>
            </div>
            <div>Label 4 (ACK Flood): <span id="count-4">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-4" style="width: 0%">0%</div></div>
            </div>
            <div>Label 5 (RST Flood): <span id="count-5">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-5" style="width: 0%">0%</div></div>
            </div>
            <div>Label 6 (HTTP Flood): <span id="count-6">0</span>
                <div class="progress-bar"><div class="progress-fill" id="bar-6" style="width: 0%">0%</div></div>
            </div>
            <div style="margin-top: 10px;"><strong>Total: <span id="count-total">0</span></strong></div>
        </div>
    </div>
    
    <h2>Select Data Label:</h2>
    <div class="button-grid">
        <button class="label-button label-0" onclick="setLabel(0)">
            0 - Normal Traffic
        </button>
        <button class="label-button label-1" onclick="setLabel(1)">
            1 - SYN Flood
        </button>
        <button class="label-button label-2" onclick="setLabel(2)">
            2 - ICMP Flood
        </button>
        <button class="label-button label-3" onclick="setLabel(3)">
            3 - UDP Flood
        </button>
        <button class="label-button label-4" onclick="setLabel(4)">
            4 - ACK Flood
        </button>
        <button class="label-button label-5" onclick="setLabel(5)">
            5 - RST Flood
        </button>
        <button class="label-button label-6" onclick="setLabel(6)">
            6 - HTTP Flood
        </button>
    </div>
    
    <div class="instruction" id="instruction">
        <h3>Instructions:</h3>
        <p id="instruction-text">Select a label above</p>
    </div>
    
    <script>
        const instructions = {
            0: {
                text: "Generate Normal Traffic",
                commands: [
                    "mininet> h1 ping -c 20 h3",
                    "mininet> h2 ping -c 20 h4",
                    "mininet> h3 iperf -s &",
                    "mininet> h1 iperf -c 10.0.0.3 -t 30",
                    "mininet> h3 killall iperf"
                ]
            },
            1: {
                text: "Generate SYN Flood Attack",
                commands: [
                    "mininet> h1 hping3 -S --flood -p 80 10.0.0.3 &",
                    "Wait 30-60 seconds...",
                    "mininet> h1 killall hping3"
                ]
            },
            2: {
                text: "Generate ICMP Flood Attack",
                commands: [
                    "mininet> h1 hping3 --icmp --flood 10.0.0.3 &",
                    "Wait 30-60 seconds...",
                    "mininet> h1 killall hping3"
                ]
            },
            3: {
                text: "Generate UDP Flood Attack",
                commands: [
                    "mininet> h1 hping3 --udp --flood -p 53 10.0.0.3 &",
                    "Wait 30-60 seconds...",
                    "mininet> h1 killall hping3"
                ]
            },
            4: {
                text: "Generate ACK Flood Attack",
                commands: [
                    "mininet> h1 hping3 -A --flood -p 80 10.0.0.3 &",
                    "Wait 30-60 seconds...",
                    "mininet> h1 killall hping3"
                ]
            },
            5: {
                text: "Generate RST Flood Attack",
                commands: [
                    "mininet> h1 hping3 -R --flood -p 80 10.0.0.3 &",
                    "Wait 30-60 seconds...",
                    "mininet> h1 killall hping3"
                ]
            },
            6: {
                text: "Generate HTTP Flood Attack",
                commands: [
                    "mininet> h3 python -m http.server 80 &",
                    "mininet> h1 while true; do curl http://10.0.0.3/ > /dev/null 2>&1; done &",
                    "mininet> h2 while true; do curl http://10.0.0.3/ > /dev/null 2>&1; done &",
                    "Wait 60 seconds...",
                    "mininet> h1 killall -9 bash curl",
                    "mininet> h2 killall -9 bash curl",
                    "mininet> h3 killall python"
                ]
            }
        };
        
        function setLabel(label) {
            fetch('/set_label', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({label: label})
            })
            .then(response => response.json())
            .then(data => {
                updateStatus();
                showInstructions(label);
            });
        }
        
        function showInstructions(label) {
            const inst = instructions[label];
            let html = '<h3>' + inst.text + '</h3>';
            inst.commands.forEach(cmd => {
                html += '<div class="command">' + cmd + '</div>';
            });
            document.getElementById('instruction-text').innerHTML = html;
        }
        
        function updateStatus() {
            fetch('/get_status')
            .then(response => response.json())
            .then(data => {
                document.getElementById('current-label').textContent = 
                    data.label + ' - ' + data.attack_type;
                
                let total = 0;
                for (let i = 0; i <= 6; i++) {
                    const count = data.samples[i.toString()] || 0;
                    total += count;
                    document.getElementById('count-' + i).textContent = count;
                    
                    const percentage = Math.min((count / 150) * 100, 100);
                    const bar = document.getElementById('bar-' + i);
                    bar.style.width = percentage + '%';
                    bar.textContent = Math.round(percentage) + '%';
                    bar.style.background = count >= 150 ? '#4CAF50' : (count >= 100 ? '#FF9800' : '#f44336');
                }
                
                document.getElementById('count-total').textContent = total;
                
                document.querySelectorAll('.label-button').forEach(btn => {
                    btn.classList.remove('current');
                });
                document.querySelector('.label-' + data.label).classList.add('current');
            });
        }
        
        setInterval(updateStatus, 2000);
        updateStatus();
    </script>
</body>
</html>
            ''')
        
        @self.app.route('/set_label', methods=['POST'])
        def set_label():
            data = request.get_json()
            label = data['label']
            
            label_map = {
                0: 'Normal',
                1: 'SYN Flood',
                2: 'ICMP Flood',
                3: 'UDP Flood',
                4: 'ACK Flood',
                5: 'RST Flood',
                6: 'HTTP Flood'
            }
            
            self.current_label = label
            self.current_attack_type = label_map[label]
            
            self.logger.info(f"📝 Label changed to: {label} ({self.current_attack_type})")
            
            return jsonify({'success': True, 'label': label, 'attack_type': self.current_attack_type})
        
        @self.app.route('/get_status')
        def get_status():
            return jsonify({
                'label': self.current_label,
                'attack_type': self.current_attack_type,
                'samples': self.total_samples
            })

    def _run_web_server(self):
        """Run Flask web server"""
        self.app.run(host='0.0.0.0', port=5001, threaded=True, debug=False)

    def _collect_data_periodically(self):
        """Periodically collect and save traffic data"""
        while True:
            hub.sleep(self.collection_interval)
            
            flows = self.monitor.get_and_clear_stats()
            
            if not flows:
                continue
            
            samples_collected = 0
            
            for flow_tuple, stats in flows.items():
                src_ip, dst_ip = flow_tuple
                duration = time.time() - stats['start_time']
                
                row = [
                    datetime.now().isoformat(),
                    src_ip,
                    dst_ip,
                    stats['packet_count'],
                    stats['byte_count'],
                    stats['syn_count'],
                    stats['fin_count'],
                    stats['rst_count'],
                    stats['ack_count'],
                    stats['icmp_count'],
                    stats.get('udp_count', 0),
                    duration,
                    self.current_label,
                    self.current_attack_type
                ]
                
                with open(self.output_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
                
                samples_collected += 1
            
            if samples_collected > 0:
                self.total_samples[str(self.current_label)] += samples_collected
                self.logger.info(
                    f"✓ Collected {samples_collected} samples "
                    f"(Label: {self.current_label} - {self.current_attack_type}) "
                    f"[Total: {sum(self.total_samples.values())}]"
                )

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

        if not eth or eth.ethertype == 0x88cc:
            return

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