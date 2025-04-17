#!/bin/bash

echo "🔧 Updating system and installing TheListener dependencies..."

# Update & upgrade
sudo apt update && sudo apt full-upgrade -y

# Install required system packages
sudo apt install -y \
  python3 \
  python3-pip \
  nmap \
  bettercap \
  libxml2 \
  libxslt1-dev \
  libpcap-dev \
  net-tools \
  curl \
  git \
  build-essential

# Install required Python packages
pip3 install --upgrade pip
pip3 install scapy lxml

echo "✅ Setup complete! You're ready to run EvenBetterCap."
