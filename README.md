# SDN Self-Defending Network

A Software Defined Networking (SDN) security system that detects and automatically blocks DDoS attacks in real time, using a Ryu controller for network monitoring, Mininet for network simulation, and a machine learning model for attack detection — with a live UI to visualize traffic and manage blocked IPs.

> ⚠️ **Results section is a placeholder** — add your real accuracy/performance numbers once you have them finalized. A couple of minor `[FILL IN]` spots (like your Python version and UI stack) are also left for you to confirm.

![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/python-3.x-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Overview

This project simulates a network using Mininet, generates both normal and attack traffic (e.g. TCP floods) to mimic real-world DDoS scenarios, and uses the Ryu SDN controller to continuously track network statistics. A trained ML model analyzes packet transfer patterns to identify malicious IPs. When an IP is flagged, it's added to a blocklist that Ryu enforces at the flow level — denying that IP the ability to transmit data. A custom UI visualizes the network live, showing traffic movement in real time and highlighting blocked IPs in red, with a one-click option to unblock them.

## Features

- **Real-time network simulation** — Mininet creates a virtual network topology for testing
- **Simulated DDoS attacks** — generates attack traffic (e.g. TCP floods) directly via Mininet commands to mimic real DDoS behavior
- **Live traffic monitoring** — Ryu controller tracks flow/packet statistics across the network continuously
- **ML-based attack detection** — a trained model analyzes packet transfer patterns to identify malicious IPs
- **Automatic blocking** — flagged IPs are added to a blocklist that Ryu enforces, denying them permission to transmit
- **Live network visualization UI** — shows traffic moving across the network in real time
- **Visual blocking indicator** — blocked IPs are highlighted in red on the UI
- **Manual unblock control** — one-click "Unblock" button to remove an IP from the blocklist

## Tech Stack

| Layer | Tool |
|---|---|
| Network simulation | Mininet |
| SDN controller | Ryu (OpenFlow) |
| ML framework | CatBoost |
| Language | Python |
| UI | Flask(React)|

## Architecture

```
Mininet (virtual network)
      │
      ├── Normal traffic
      └── Simulated DDoS traffic (TCP flood, etc.)
                  │
                  ▼
      Ryu Controller (tracks flow/packet stats via OpenFlow)
                  │
                  ▼
         Feature Extraction (packet transfer patterns)
                  │
                  ▼
              ML Model
                  │
                  ▼
        Malicious IP? ──Yes──► Add IP to Blocklist
                  │                     │
                  No                    ▼
                  │           Ryu denies transmission
                  │           for blocklisted IP
                  ▼                     │
          Traffic allowed              ▼
                            UI shows IP as "Blocked" (red)
                                        │
                                        ▼
                          Manual "Unblock" button available
```

## How It Works

1. **Mininet** builds a virtual network topology with multiple hosts and switches.
2. Traffic is generated on this topology — both normal traffic and simulated DDoS attacks (e.g. TCP-based floods) triggered via Mininet commands.
3. The **Ryu controller** continuously tracks network statistics (packet counts, flow behavior, etc.) via OpenFlow.
4. These stats are fed into a trained **ML model**, which analyzes packet transfer patterns to identify which IPs are behaving maliciously.
5. If the model flags an IP as an attacker, that IP is added to a **blocklist**.
6. The blocklist is passed to Ryu, which then denies that IP the authority to transmit any further data on the network.
7. The **UI** visualizes the network live — showing traffic moving between nodes — and marks any blocked IP in **red**.
8. From the UI, a blocked IP can be manually **unblocked** with a single button click, removing it from the blocklist and restoring its access.

## Dataset

Custom, self-created dataset — traffic and its statistics were captured directly from the Mininet simulations and saved to Excel files. Five separate `.xlsx` files were created, each capturing a different individual attack type, plus one additional file capturing normal (benign) traffic. This combined dataset was used to train a **CatBoost** model to distinguish malicious traffic from normal traffic.

## Model

**CatBoost** classifier, trained on packet transfer/flow statistics captured per traffic type (5 attack categories + normal traffic) from the Mininet + Ryu setup.

## Results

`[TO BE ADDED]`

## Installation

```bash
git clone <your-repo-url>
cd sdn-self-defending-network
pip install -r requirements.txt
```

**Prerequisites:**
- Mininet installed and configured
- Ryu SDN controller
- Python 3.9
## Usage

**1. Launch the Mininet topology**
```bash
sudo python mininet_topology.py
```

**2. Start the Ryu controller (this also launches the UI)**
```bash
ryu-manager ryu_controller.py
```
No separate command is needed for the UI — it's served automatically once the controller starts.

**3. Generate traffic from the Mininet CLI**

Once the topology is up, use standard Mininet CLI commands to generate normal and attack traffic between hosts, for example:

```bash
# Normal traffic
mininet> h1 ping h2

# TCP attack traffic
mininet> h1 hping3 -S --flood -V h2

# UDP attack traffic
mininet> h1 hping3 --udp --flood -V h2
```

(Adjust host names and flags to match whichever attack types your topology and dataset cover.)

**4. Observe detection and blocking**

Open the UI to watch traffic move across the network live. When the CatBoost model flags an IP as malicious, it will appear highlighted in **red** and lose the ability to transmit. Use the **Unblock** button on the UI to manually restore access to a blocked IP.

## Future Work

- Extend detection to additional attack types beyond TCP-based DDoS
- Add historical logging of blocked IPs and attack events
- Experiment with deep learning–based detection models
- Test on a larger, more realistic topology

## License

MIT
