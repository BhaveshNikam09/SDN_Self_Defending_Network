# firewall/mitigation.py

from . import block_rules

class MitigationManager:
    """
    Manages the deployment of mitigation rules to all connected switches.
    """
    def __init__(self, logger):
        self.logger = logger
        self.blocked_ips = set()  # Track blocked IPs to avoid duplicates

    def block_ip_address(self, datapaths, ip_to_block, victim_ip=None):
        """
        Blocks traffic from the attacker IP address.
        
        Args:
            datapaths (dict): A dictionary of all connected datapath objects.
            ip_to_block (str): The attacker's IP address to block.
            victim_ip (str, optional): The victim's IP address. If provided, 
                                      creates more specific rules.
        """
        # Avoid blocking the same IP multiple times
        if ip_to_block in self.blocked_ips:
            self.logger.info(f"IP {ip_to_block} is already blocked. Skipping.")
            return
        
        self.blocked_ips.add(ip_to_block)
        
        if victim_ip:
            self.logger.warning(
                f"🛡️  Deploying mitigation: Blocking traffic from attacker {ip_to_block} "
                f"to victim {victim_ip} and preventing further attacks."
            )
        else:
            self.logger.warning(
                f"🛡️  Deploying mitigation: Blocking all outgoing traffic from {ip_to_block}."
            )

        blocked_count = 0
        for datapath in datapaths.values():
            try:
                if victim_ip:
                    # Create bidirectional rules (attacker->victim and attacker->all)
                    flow_mod_msgs = block_rules.create_bidirectional_drop_rules(
                        datapath, ip_to_block, victim_ip
                    )
                    for msg in flow_mod_msgs:
                        datapath.send_msg(msg)
                    blocked_count += 1
                else:
                    # Create simple source-based drop rule
                    flow_mod_msg = block_rules.create_flow_mod_to_drop(datapath, ip_to_block)
                    datapath.send_msg(flow_mod_msg)
                    blocked_count += 1
            except Exception as e:
                self.logger.error(f"Failed to install blocking rule on switch {datapath.id}: {e}")
        
        if blocked_count > 0:
            self.logger.info(f"✅ Successfully deployed blocking rules for {ip_to_block} on {blocked_count} switch(es).")
        else:
            self.logger.error(f"❌ Failed to deploy any blocking rules for {ip_to_block}")