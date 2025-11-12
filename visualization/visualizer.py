# visualization/visualizer.py

from flask import Flask, jsonify, render_template_string
from ryu.lib import hub
import os

class Visualizer:
    def __init__(self, logger, traffic_monitor, attack_detector=None):
        self.logger = logger
        self.traffic_monitor = traffic_monitor
        self.attack_detector = attack_detector  # Reference to attack detector
        self.nodes = []
        self.links = []
        self.ip_to_mac = {}
        
        static_folder_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
        self.app = Flask(__name__, static_folder=static_folder_path)
        
        self.web_thread = hub.spawn(self.run_web_server)
        self._setup_routes()

        # Log initialization
        if self.attack_detector:
            self.logger.info("Visualizer initialized with attack detection dashboard")
        else:
            self.logger.info("Visualizer initialized - using event-based topology discovery")

    def run_web_server(self):
        try:
            self.app.run(host='0.0.0.0', port=5000, threaded=True)
        except Exception as e:
            self.logger.error(f"Web server failed: {e}")

    def _setup_routes(self):
        self.app.add_url_rule('/', 'index', self._serve_index_page)
        self.app.add_url_rule('/api/topology', 'topology_data', self._serve_topology_data)
        self.app.add_url_rule('/api/traffic', 'traffic_data', self._serve_traffic_data)
        self.app.add_url_rule('/api/attack_summary', 'attack_summary', self._serve_attack_summary)

    def _serve_topology_data(self):
        return jsonify({'nodes': self.nodes, 'links': self.links, 'ip_to_mac': self.ip_to_mac})

    def _serve_traffic_data(self):
        active_flows = list(self.traffic_monitor.flow_stats.keys())
        return jsonify({'flows': active_flows})
    
    def _serve_attack_summary(self):
        """Serves current attack statistics."""
        if self.attack_detector:
            summary = self.attack_detector.get_attack_summary()
            attack_types = self.attack_detector.get_attacks_by_type()
            top_victims = self.attack_detector.get_top_victims(top_n=5)
            
            return jsonify({
                'total_attackers': summary['total_attackers'],
                'total_victims': len(summary.get('known_victims', [])),
                'blocked_ips': summary['blocked_ips'],
                'known_victims': summary.get('known_victims', []),
                'attack_types': attack_types,
                'top_victims': top_victims,
                'attack_records': summary['attack_records']
            })
        else:
            return jsonify({
                'total_attackers': 0,
                'total_victims': 0,
                'blocked_ips': {},
                'known_victims': [],
                'attack_types': {},
                'top_victims': [],
                'attack_records': []
            })

    def handle_switch_enter(self, ev):
        switch_dpid = ev.switch.dp.id
        node_id = f's{switch_dpid}'
        self.logger.info(f"Visualizer: Switch {node_id} entered.")
        node = {'id': node_id, 'label': f'Switch {switch_dpid}', 'group': 'switch'}
        if not any(n['id'] == node_id for n in self.nodes):
            self.nodes.append(node)

    def handle_link_add(self, ev):
        src_dpid = ev.link.src.dpid
        dst_dpid = ev.link.dst.dpid
        self.logger.info(f"Visualizer: Link discovered between s{src_dpid} and s{dst_dpid}.")

        # Create a sorted, canonical ID to handle bi-directional links
        sorted_dpids = sorted((src_dpid, dst_dpid))
        link_id = f"s{sorted_dpids[0]}-s{sorted_dpids[1]}"
        
        link = {'id': link_id, 'from': f's{src_dpid}', 'to': f's{dst_dpid}'}
        
        # Check if this canonical link already exists before adding
        if not any(l['id'] == link_id for l in self.links):
            self.links.append(link)
            self.logger.info(f"Visualizer: Added link {link_id} to topology.")
    
    def handle_host_add(self, ev):
        host = ev.host
        host_ip = host.ipv4[0] if host.ipv4 else 'N/A'
        host_mac = host.mac
        connected_switch_dpid = host.port.dpid
        self.logger.info(f"Visualizer: Host {host_ip} (MAC: {host_mac}) discovered on s{connected_switch_dpid}.")
        self.ip_to_mac[host_ip] = host_mac
        host_node_id = host_mac
        host_node = {'id': host_node_id, 'label': f'Host\n{host_ip}', 'group': 'normal'}
        if not any(n['id'] == host_node_id for n in self.nodes):
            self.nodes.append(host_node)
        switch_node_id = f's{connected_switch_dpid}'
        link_id = f"{host_node_id}-{switch_node_id}"
        link = {'id': link_id, 'from': host_node_id, 'to': switch_node_id}
        if not any(l['id'] == link_id for l in self.links):
            self.links.append(link)

    def update_node_status(self, ip_address, status):
        mac_address = self.ip_to_mac.get(ip_address)
        if not mac_address: return
        for node in self.nodes:
            if node.get('id') == mac_address:
                node['group'] = status
                self.logger.info(f"Visualizer: Updated status of {ip_address} to '{status}'.")
                break
    
    def _serve_index_page(self):
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SDN Network Visualization</title>
            <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
            <style type="text/css">
                body, html { font-family: Arial, sans-serif; margin: 0; padding: 0; height: 100%; overflow: hidden; }
                h1 { text-align: center; background-color: #f2f2f2; padding: 10px; margin: 0; }
                #mynetwork { width: 100%; height: 90vh; border: 1px solid lightgray; }
                #status-panel {
                    position: absolute; top: 60px; right: 10px; width: 220px;
                    background-color: rgba(255, 255, 255, 0.95); border: 1px solid #ccc;
                    border-radius: 8px; padding: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    max-height: 400px; overflow-y: auto;
                }
                #attack-panel {
                    position: absolute; top: 60px; left: 10px; width: 350px;
                    background-color: rgba(255, 255, 255, 0.95); border: 1px solid #ccc;
                    border-radius: 8px; padding: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    max-height: 500px; overflow-y: auto;
                }
                #debug-panel {
                    position: absolute; bottom: 10px; left: 10px; width: 300px;
                    background-color: rgba(255, 255, 255, 0.95); border: 1px solid #ccc;
                    border-radius: 8px; padding: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                    font-size: 12px; max-height: 150px; overflow-y: auto;
                }
                .panel-header {
                    margin: 0 0 10px 0;
                    padding-bottom: 8px;
                    border-bottom: 2px solid #e0e0e0;
                    font-size: 16px;
                    font-weight: bold;
                    color: #333;
                }
                .status-item { margin: 8px 0; font-size: 13px; padding: 5px; border-radius: 4px; }
                .status-normal { color: #2e7d32; background-color: #e8f5e9; }
                .status-blocked { color: #c62828; background-color: #ffebee; font-weight: bold; }
                .attack-stat {
                    background-color: #f5f5f5;
                    padding: 10px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border-left: 4px solid #ff5722;
                }
                .attack-stat-header {
                    font-weight: bold;
                    color: #d32f2f;
                    margin-bottom: 5px;
                }
                .victim-stat {
                    background-color: #e3f2fd;
                    padding: 10px;
                    margin: 8px 0;
                    border-radius: 6px;
                    border-left: 4px solid #2196f3;
                }
                .victim-stat-header {
                    font-weight: bold;
                    color: #1976d2;
                    margin-bottom: 5px;
                }
                .attack-log-item {
                    font-size: 12px;
                    padding: 8px;
                    margin: 5px 0;
                    background-color: #fafafa;
                    border-radius: 4px;
                    border-left: 3px solid #ff9800;
                }
                .attack-log-time {
                    color: #666;
                    font-size: 11px;
                }
                .no-attacks {
                    text-align: center;
                    padding: 20px;
                    color: #4caf50;
                    font-weight: bold;
                }
            </style>
        </head>
        <body>
            <h1>Live Network Topology & Security Dashboard</h1> 
            <div id="mynetwork"></div>
            
            <div id="attack-panel">
                <h2 class="panel-header">🚨 Attack Summary</h2>
                <div id="attack-stats"></div>
            </div>
            
            <div id="status-panel"> 
                <h2 class="panel-header">📊 Host Status</h2> 
                <div id="status-list"></div> 
            </div>
            
            <div id="debug-panel">
                <h3 style="margin-top: 0;">🔧 Topology Info</h3>
                <div id="debug-info"></div>
            </div>
            <script type="text/javascript">
                const container = document.getElementById('mynetwork');
                const nodes = new vis.DataSet([]);
                const edges = new vis.DataSet([]);
                const network = new vis.Network(container, { nodes, edges }, {});
                let ipToMac = {};

                function updateDebugInfo(data) {
                    const debugDiv = document.getElementById('debug-info');
                    const switchCount = data.nodes.filter(n => n.group === 'switch').length;
                    const hostCount = data.nodes.filter(n => n.group !== 'switch').length;
                    const switchLinks = data.links.filter(l => l.from.startsWith('s') && l.to.startsWith('s'));
                    const hostLinks = data.links.filter(l => !(l.from.startsWith('s') && l.to.startsWith('s')));
                    
                    debugDiv.innerHTML = `
                        <div><strong>Switches:</strong> ${switchCount}</div>
                        <div><strong>Hosts:</strong> ${hostCount}</div>
                        <div><strong>Switch Links:</strong> ${switchLinks.length}</div>
                        <div><strong>Host Links:</strong> ${hostLinks.length}</div>
                        <div style="margin-top: 5px; font-size: 10px; color: #666;">
                            ${switchLinks.length > 0 ? 'Links: ' + switchLinks.map(l => l.id).join(', ') : 'No switch links yet'}
                        </div>
                    `;
                }

                async function updateTopology() {
                    try {
                        const response = await fetch('/api/topology');
                        const data = await response.json();
                        ipToMac = data.ip_to_mac;
                        
                        console.log('Topology update:', {
                            nodes: data.nodes.length,
                            links: data.links.length,
                            switchLinks: data.links.filter(l => l.from.startsWith('s') && l.to.startsWith('s')).length
                        });
                        
                        // Update nodes
                        const existingNodeIds = new Set(nodes.getIds());
                        const newNodeIds = new Set(data.nodes.map(n => n.id));
                        
                        // Remove nodes that no longer exist
                        existingNodeIds.forEach(id => {
                            if (!newNodeIds.has(id)) {
                                nodes.remove(id);
                            }
                        });
                        
                        // Update or add new nodes
                        nodes.update(data.nodes);
                        
                        // Update edges
                        const existingEdgeIds = new Set(edges.getIds());
                        const newEdgeIds = new Set(data.links.map(l => l.id));
                        
                        // Remove edges that no longer exist
                        existingEdgeIds.forEach(id => {
                            if (!newEdgeIds.has(id)) {
                                edges.remove(id);
                            }
                        });
                        
                        // Update or add new edges
                        edges.update(data.links);
                        
                        updateStatusPanel(data.nodes);
                        updateDebugInfo(data);
                    } catch (error) {
                        console.error('Error updating topology:', error);
                    }
                }

                function updateStatusPanel(allNodes) {
                    const statusList = document.getElementById('status-list');
                    statusList.innerHTML = '';
                    
                    const hosts = allNodes.filter(n => n.group === 'normal' || n.group === 'blocked');
                    
                    if (hosts.length === 0) {
                        statusList.innerHTML = '<div style="text-align: center; color: #999;">No hosts detected</div>';
                        return;
                    }
                    
                    hosts.forEach(node => {
                        const statusItem = document.createElement('div');
                        statusItem.className = 'status-item';
                        const statusClass = node.group === 'blocked' ? 'status-blocked' : 'status-normal';
                        const statusIcon = node.group === 'blocked' ? '🚫' : '✓';
                        const statusText = node.group === 'blocked' ? 'Blocked' : 'Normal';
                        const ipMatch = node.label.match(/\d+\.\d+\.\d+\.\d+/);
                        const ipAddress = ipMatch ? ipMatch[0] : 'Unknown';
                        statusItem.className += ' ' + statusClass;
                        statusItem.innerHTML = `<strong>${ipAddress}</strong><br/>${statusIcon} ${statusText}`;
                        statusList.appendChild(statusItem);
                    });
                }
                
                async function updateAttackSummary() {
                    try {
                        const response = await fetch('/api/attack_summary');
                        const data = await response.json();
                        const attackStats = document.getElementById('attack-stats');
                        
                        if (data.total_attackers === 0) {
                            attackStats.innerHTML = '<div class="no-attacks">✅ No Active Threats<br/>Network Secure</div>';
                            return;
                        }
                        
                        let html = '';
                        
                        // Summary stats
                        html += `
                            <div class="attack-stat">
                                <div class="attack-stat-header">🚫 Blocked Attackers: ${data.total_attackers}</div>
                                ${Object.entries(data.blocked_ips).map(([ip, type]) => 
                                    `<div style="margin: 5px 0; font-size: 12px;">• ${ip} (${type})</div>`
                                ).join('')}
                            </div>
                        `;
                        
                        // Victim stats
                        if (data.total_victims > 0) {
                            html += `
                                <div class="victim-stat">
                                    <div class="victim-stat-header">🛡️ Protected Victims: ${data.total_victims}</div>
                                    ${data.known_victims.map(ip => 
                                        `<div style="margin: 5px 0; font-size: 12px;">• ${ip}</div>`
                                    ).join('')}
                                </div>
                            `;
                        }
                        
                        // Attack types
                        if (Object.keys(data.attack_types).length > 0) {
                            html += `
                                <div style="background-color: #fff3e0; padding: 10px; margin: 8px 0; border-radius: 6px;">
                                    <div style="font-weight: bold; color: #e65100; margin-bottom: 5px;">📈 Attack Types</div>
                                    ${Object.entries(data.attack_types).map(([type, count]) => 
                                        `<div style="font-size: 12px; margin: 3px 0;">• ${type}: ${count}</div>`
                                    ).join('')}
                                </div>
                            `;
                        }
                        
                        // Top victims
                        if (data.top_victims && data.top_victims.length > 0) {
                            html += `
                                <div style="background-color: #fce4ec; padding: 10px; margin: 8px 0; border-radius: 6px;">
                                    <div style="font-weight: bold; color: #c2185b; margin-bottom: 5px;">🎯 Most Targeted</div>
                                    ${data.top_victims.map(([ip, count], index) => 
                                        `<div style="font-size: 12px; margin: 3px 0;">${index + 1}. ${ip} (${count}x)</div>`
                                    ).join('')}
                                </div>
                            `;
                        }
                        
                        // Recent attacks (last 5)
                        if (data.attack_records && data.attack_records.length > 0) {
                            const recentAttacks = data.attack_records.slice(-5).reverse();
                            html += `
                                <div style="margin-top: 10px;">
                                    <div style="font-weight: bold; color: #333; margin-bottom: 5px;">📝 Recent Attacks</div>
                                    ${recentAttacks.map(record => {
                                        const time = new Date(record.timestamp * 1000).toLocaleTimeString();
                                        return `
                                            <div class="attack-log-item">
                                                <div class="attack-log-time">${time}</div>
                                                <div style="font-weight: bold; color: #d32f2f;">${record.attack_type}</div>
                                                <div style="font-size: 11px; margin-top: 3px;">
                                                    ${record.attacker} → ${record.victim}
                                                </div>
                                            </div>
                                        `;
                                    }).join('')}
                                </div>
                            `;
                        }
                        
                        attackStats.innerHTML = html;
                    } catch (error) {
                        console.error('Error updating attack summary:', error);
                    }
                }
                
                async function animateTraffic() {
                    try {
                        const trafficResponse = await fetch('/api/traffic');
                        const trafficData = await trafficResponse.json();
                        let activeEdges = new Set();
                        
                        trafficData.flows.forEach(flow => {
                            const [srcIp, dstIp] = flow;
                            const srcMac = ipToMac[srcIp];
                            const dstMac = ipToMac[dstIp];
                            
                            if (srcMac && dstMac) {
                                const edge1 = edges.get({ filter: item => item.from === srcMac || item.to === srcMac });
                                if (edge1.length > 0) activeEdges.add(edge1[0].id);
                                const edge2 = edges.get({ filter: item => item.from === dstMac || item.to === dstMac });
                                if (edge2.length > 0) activeEdges.add(edge2[0].id);
                            }
                        });

                        const edgeUpdates = [];
                        edges.getIds().forEach(edgeId => {
                            if (activeEdges.has(edgeId)) {
                                edgeUpdates.push({ id: edgeId, color: { color: '#FF5733' }, width: 4, arrows: { to: { enabled: true, type: 'arrow' } } });
                            } else {
                                edgeUpdates.push({ id: edgeId, color: { color: '#848484' }, width: 2, arrows: { to: { enabled: false } } });
                            }
                        });
                        edges.update(edgeUpdates);
                    } catch (error) {
                        console.error('Error animating traffic:', error);
                    }
                }
                
                function configureNetwork() {
                    const options = {
                        nodes: { 
                            font: { size: 14, color: '#000000' },
                            borderWidth: 2
                        },
                        edges: { 
                            width: 2, 
                            color: '#848484',
                            smooth: {
                                enabled: true,
                                type: 'continuous'
                            }
                        },
                        physics: { 
                            enabled: true,
                            stabilization: { 
                                enabled: true,
                                iterations: 200 
                            },
                            barnesHut: {
                                gravitationalConstant: -10000,
                                springConstant: 0.05,
                                springLength: 200,
                                avoidOverlap: 0.5
                            }
                        },
                        layout: { 
                            improvedLayout: true,
                            hierarchical: false
                        },
                        groups: {
                            normal: { 
                                shape: 'dot', 
                                color: { background: '#97C2FC', border: '#2B7CE9' }, 
                                size: 25 
                            },
                            blocked: { 
                                shape: 'dot', 
                                color: { background: '#F08080', border: '#D32F2F' }, 
                                size: 30,
                                borderWidth: 3
                            },
                            switch: { 
                                shape: 'box', 
                                color: { background: '#FFC300', border: '#FF8C00' }, 
                                size: 30,
                                font: { size: 16, color: '#000000', bold: true }
                            }
                        }
                    };
                    network.setOptions(options);
                    updateTopology();
                }
                
                configureNetwork();
                
                // Update topology and attacks every 2 seconds
                setInterval(() => {
                    updateTopology();
                    animateTraffic();
                    updateAttackSummary();
                }, 2000);
                
                // Initial attack summary load
                updateAttackSummary();
            </script>
        </body>
        </html>
        """)