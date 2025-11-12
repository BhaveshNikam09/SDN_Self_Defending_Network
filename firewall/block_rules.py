# firewall/block_rules.py

def create_flow_mod_to_drop(datapath, ip_src):
    """
    Creates and returns an OFPFlowMod message to drop packets from a specific IP.
    This blocks OUTGOING traffic from the attacker (their source IP).
    """
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    
    # Match packets with the specified source IP address
    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
    
    # An empty action list means "drop the packet"
    actions = []
    
    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    
    # Create the FlowMod message
    # We give it a high priority to ensure it's matched before any other rule
    mod = parser.OFPFlowMod(
        datapath=datapath,
        priority=100,  # High priority
        match=match,
        instructions=instructions,
        hard_timeout=600  # Rule will be removed after 10 minutes
    )
    
    return mod


def create_bidirectional_drop_rules(datapath, attacker_ip, victim_ip):
    """
    Creates flow rules to block ONLY traffic from attacker to victim.
    This prevents blocking legitimate traffic from victim to other hosts.
    
    Returns a list of flow mod messages.
    """
    parser = datapath.ofproto_parser
    ofproto = datapath.ofproto
    
    rules = []
    
    # Rule 1: Drop packets FROM attacker TO victim
    match_attack = parser.OFPMatch(
        eth_type=0x0800, 
        ipv4_src=attacker_ip,
        ipv4_dst=victim_ip
    )
    actions = []
    instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    
    mod_attack = parser.OFPFlowMod(
        datapath=datapath,
        priority=100,
        match=match_attack,
        instructions=instructions,
        hard_timeout=600
    )
    rules.append(mod_attack)
    
    # Rule 2: Drop packets FROM attacker TO ANY destination (complete isolation)
    # This ensures the attacker can't attack anyone else
    match_attacker_all = parser.OFPMatch(
        eth_type=0x0800, 
        ipv4_src=attacker_ip
    )
    
    mod_attacker_all = parser.OFPFlowMod(
        datapath=datapath,
        priority=90,  # Slightly lower priority than specific rule
        match=match_attacker_all,
        instructions=instructions,
        hard_timeout=600
    )
    rules.append(mod_attacker_all)
    
    return rules