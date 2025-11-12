#!/bin/bash

# ==============================================================================
# start_network.sh
#
# This script automates the startup of the SDN project components.
# It opens separate terminal tabs for the Ryu Controller and Mininet CLI.
#
# USAGE:
# Run from the root directory of the project:
# sudo ./scripts/start_network.sh
# ==============================================================================

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo."
  exit
fi

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Determine which terminal to use
if command_exists gnome-terminal; then
  TERMINAL_CMD="gnome-terminal"
elif command_exists xterm; then
  TERMINAL_CMD="xterm -e"
else
  echo "Error: Neither gnome-terminal nor xterm is installed."
  echo "Cannot open new terminal windows."
  exit 1
fi

echo "--- Starting SDN Self-Defending Network ---"

# Start Ryu Controller in a new terminal tab
echo "[1] Starting Ryu Controller..."
$TERMINAL_CMD --tab --title="Ryu Controller" -- bash -c "ryu-manager ./controller/main_controller.py; exec bash" &

# Wait a few seconds for the controller to initialize
echo "Waiting for controller to start..."
sleep 5

# Start Mininet in a new terminal tab
echo "[2] Starting Mininet Topology..."
$TERMINAL_CMD --tab --title="Mininet CLI" -- bash -c "python3 ./mininet_topology/topology.py; exec bash" &

echo "--- All components started in new terminal tabs. ---"