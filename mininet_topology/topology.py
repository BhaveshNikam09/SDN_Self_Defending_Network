#!/usr/bin/env python3
"""
Interactive Dynamic Mininet Topology for SDN Self-Defending Network.
Prompts user for the number of switches and hosts at runtime.
Can also accept command-line arguments for automation.
"""
import argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import socket
import sys

def check_port(ip, port):
    """Check if a port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0

def configure_sflow(net, collector_ip='127.0.0.1', collector_port=6343):
    """Configures sFlow on all switches in the network."""
    info(f'*** Configuring sFlow to send stats to {collector_ip}:{collector_port}\n')
    sflow_cmd = (
        f"ovs-vsctl -- --id=@sflow create sflow agent=eth0 "
        f"target=\\\"\"{collector_ip}:{collector_port}\\\"\" "
        f"header=128 sampling=400 polling=10 -- "
    )
    for switch in net.switches:
        cmd = sflow_cmd + f"set bridge {switch.name} sflow=@sflow"
        switch.cmd(cmd)

def get_user_input():
    """Prompt user for topology parameters with validation."""
    print("\n" + "="*50)
    print("  Dynamic Mininet Topology Configuration")
    print("="*50 + "\n")
    
    while True:
        try:
            num_switches = int(input("Enter the number of switches (1-20): "))
            if 1 <= num_switches <= 20:
                break
            else:
                print("❌ Please enter a number between 1 and 20.")
        except ValueError:
            print("❌ Invalid input. Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\n👋 Exiting...")
            sys.exit(0)
    
    while True:
        try:
            num_hosts = int(input("Enter the number of hosts (1-50): "))
            if 1 <= num_hosts <= 50:
                break
            else:
                print("❌ Please enter a number between 1 and 50.")
        except ValueError:
            print("❌ Invalid input. Please enter a valid number.")
        except KeyboardInterrupt:
            print("\n\n👋 Exiting...")
            sys.exit(0)
    
    print("\n" + "-"*50)
    print(f"✓ Configuration: {num_switches} switches, {num_hosts} hosts")
    print("-"*50 + "\n")
    
    return num_switches, num_hosts

def create_topology(num_switches, num_hosts):
    """Creates a dynamic Mininet topology."""
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    # Find and add the controller
    ip = '127.0.0.1'
    port = 6653 if check_port(ip, 6653) else 6633
    info(f'*** Adding controller (using port {port})\n')
    net.addController('c0', controller=RemoteController, ip=ip, port=port)

    # Create switches
    info(f'*** Adding {num_switches} switches\n')
    switches = [net.addSwitch(f's{i+1}') for i in range(num_switches)]

    # Create hosts
    info(f'*** Adding {num_hosts} hosts\n')
    hosts = [net.addHost(f'h{i+1}', ip=f'10.0.0.{i+1}/24') for i in range(num_hosts)]

    info('*** Creating links\n')
    # Link switches in a line: s1-s2-s3...
    for i in range(num_switches - 1):
        info(f'Linking {switches[i].name} to {switches[i+1].name}\n')
        net.addLink(switches[i], switches[i+1])

    # Distribute hosts evenly among the switches
    for i, host in enumerate(hosts):
        switch_index = i % num_switches
        info(f'Linking {host.name} to {switches[switch_index].name}\n')
        net.addLink(host, switches[switch_index])

    info('*** Starting network\n')
    net.start()

    # Configure sFlow if needed
    # configure_sflow(net)

    info('\n' + '='*50)
    info('\n*** Network is ready! You can now use Mininet CLI commands.')
    info('\n*** Type "help" for available commands, "exit" to quit.')
    info('\n' + '='*50 + '\n')
    
    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    
    # Argument parser for optional command-line usage
    parser = argparse.ArgumentParser(
        description="Create an interactive dynamic Mininet topology.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode (prompts for input):
    sudo python3 topology.py
  
  Command-line mode:
    sudo python3 topology.py -s 4 -H 8
    sudo python3 topology.py --switches 5 --hosts 10
        """
    )
    parser.add_argument(
        '-s', '--switches', 
        type=int, 
        help="Number of switches to create (1-20)"
    )
    parser.add_argument(
        '-H', '--hosts', 
        type=int, 
        help="Total number of hosts to create (1-50)"
    )
    args = parser.parse_args()

    # If arguments provided, use them; otherwise, prompt user
    if args.switches is not None and args.hosts is not None:
        # Validate command-line arguments
        if not (1 <= args.switches <= 20):
            print("❌ Error: Number of switches must be between 1 and 20")
            sys.exit(1)
        if not (1 <= args.hosts <= 50):
            print("❌ Error: Number of hosts must be between 1 and 50")
            sys.exit(1)
        
        num_switches = args.switches
        num_hosts = args.hosts
        print(f"\n✓ Using command-line arguments: {num_switches} switches, {num_hosts} hosts\n")
    elif args.switches is not None or args.hosts is not None:
        print("❌ Error: Both --switches and --hosts must be provided together")
        sys.exit(1)
    else:
        # Interactive mode - prompt user
        num_switches, num_hosts = get_user_input()

    create_topology(num_switches, num_hosts)