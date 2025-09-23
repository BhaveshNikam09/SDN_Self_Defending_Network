#!/usr/bin/env python3
"""
Mininet Topology for SDN Self-Defending Network
Auto-detects Ryu controller port (6653 or 6633).
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import socket

def check_port(ip, port):
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def create_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    ip = '127.0.0.1'
    port = 6653 if check_port(ip, 6653) else 6633

    info(f'*** Adding controller (using port {port})\n')
    c0 = net.addController('c0',
                           controller=RemoteController,
                           ip=ip, port=port)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    attacker = net.addHost('attacker', ip='10.0.0.100/24')

    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(attacker, s1)

    info('*** Starting network\n')
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
