# PeerVision - WireGuard Peer Management Web Interface

## Overview

PeerVision is a web-based GUI tool for managing WireGuard peers on your active interface. It allows you to add, remove, enable, disable, and view peer status, while also tracking peers traffic usage persistently, even across interface resets. With an intuitive design and security features like IP-based access control, PeerVision simplifies WireGuard peer management without the need for complex commands.

## Features

- Web-based graphical interface for WireGuard peer management
- Secure access for peers connected to the WireGuard VPN
- Comprehensive peer configuration options

## Requirements

- WireGuard VPN
- [wgctl](https://github.com/snaeim/wgctl) (WireGuard Control CLI)  
- [wgstat](https://github.com/snaeim/wgstat) (WireGuard Traffic Statistics Persistence)
- Python 3
- Systemd

## Installation

Run the following command with sudo privileges:

```bash
sudo bash -c "$(wget -qO- https://raw.githubusercontent.com/snaeim/peervision/refs/heads/main/installer.sh)"
```

## Access

1. Create Interface with wgctl: You must first create a WireGuard interface using the `wgctl` tool to configure the network for the peers.
2. Peer Creation for Interface Detection: A peer must be created under the interface to enable the server to detect and associate the correct interface based on the peer’s IP.
3. Web Panel Access: Once the interface and peer are configured, you can connect to the web panel using the server's public IP address at port 10088 to manage and control the peers linked to that interface.

## How It Works

Each peer connected to the WireGuard VPN can:
- View interface details
- Add new peers
- Remove existing peers
- Enable or disable peer access
- Export peer configurations

## Contributing

Contributions are welcome. Please submit pull requests or open issues on the GitHub repository.