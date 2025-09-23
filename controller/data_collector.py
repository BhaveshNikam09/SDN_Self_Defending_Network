# data_collector.py

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, icmp
from ryu.lib import hub

from collections import defaultdict
import csv
import os
import time

class DataCollector(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DataCollector, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Data structure to hold flow information
        # Key: (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flow_data = defaultdict(lambda: {
            'packet_count': 0, 'byte_count': 0, 'syn_count': 0, 
            'fin_count': 0, 'rst_count': 0, 'ack_count': 0,
            'icmp_count': 0
        })
        self.output_file = 'flow_data.csv'
        self.collection_interval = 10 # seconds

        # Start the thread to periodically write data to CSV
        self.file_writing_thread = hub.spawn(self._write_to_csv)
        self.logger.info("Data Collector Started. Writing to %s every %d seconds.", 
                         self.output_file, self.collection_interval)

    def _write_to_csv(self):
        """Periodically writes the collected flow data to a CSV file."""
        # Write the header row if the file doesn't exist
        file_exists = os.path.isfile(self.output_file)
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
                    'packet_count', 'byte_count', 'syn_count', 'fin_count', 
                    'rst_count', 'ack_count', 'icmp_count', 'duration_sec'
                ])
        
        while True:
            hub.sleep(self.collection_interval)
            
            # Create a copy to avoid issues with concurrent modification
            data_to_write = list(self.flow_data.items())
            self.flow_data.clear()

            with open(self.output_file, 'a', newline='') as f:
                writer = csv.writer(f)
                for (src_ip, dst_ip, src_port, dst_port, proto), stats in data_to_write:
                    writer.writerow([
                        int(time.time()), src_ip, dst_ip, src_port, dst_port, proto,
                        stats['packet_count'], stats['byte_count'], stats['syn_count'],
                        stats['fin_count'], stats['rst_count'], stats['ack_count'],
                        stats['icmp_count'], self.collection_interval
                    ])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install a table-miss flow entry to send all packets to the controller."""
        # (This handler remains the same as your previous controller)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=[
                                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)])
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Main handler for incoming packets to extract features."""
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # --- Basic L2 switching logic (to keep the network running) ---
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(eth.dst, datapath.ofproto.OFPP_FLOOD)
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        # --- Feature Extraction Logic ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            proto = ip_pkt.proto
            src_port, dst_port = 0, 0 # Default for non-TCP/UDP packets

            flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
            
            # Extract TCP info
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                src_port, dst_port = tcp_pkt.src_port, tcp_pkt.dst_port
                flow_key = (src_ip, dst_ip, src_port, dst_port, proto)
                if tcp_pkt.bits & 0b000010: self.flow_data[flow_key]['syn_count'] += 1
                if tcp_pkt.bits & 0b000001: self.flow_data[flow_key]['fin_count'] += 1
                if tcp_pkt.bits & 0b000100: self.flow_data[flow_key]['rst_count'] += 1
                if tcp_pkt.bits & 0b010000: self.flow_data[flow_key]['ack_count'] += 1
            
            # Extract ICMP info
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                self.flow_data[flow_key]['icmp_count'] += 1

            # Update generic stats
            self.flow_data[flow_key]['packet_count'] += 1
            self.flow_data[flow_key]['byte_count'] += len(msg.data)

        # --- Forward the packet ---
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=msg.data)
        datapath.send_msg(out)