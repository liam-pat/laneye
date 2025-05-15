# LANEYE

A Go-based network scanning tool that helps you discover devices on your local network.

## Features

- 🔍 Scan and identify all devices on your local network
- 📱 Display device information including IP and MAC addresses
- 🏢 Show vendor information for discovered devices
- 🔒 Help identify potential security concerns (e.g., hidden cameras)
- 🚀 Fast and efficient scanning using Go

## Prerequisites

- Go 1.16 or higher
- Root/sudo privileges (required for network scanning)

## Installation

```bash
git clone https://github.com/liam-pat/laneye.git
cd laneye & go build

sudo ./laneye --interface=en0
```

## How It Works

The tool uses network packet manipulation to:
1. Calculate the local network range
2. Send ARP requests to all possible hosts
3. Collect and display responses with device information

For more information about network calculations, check out this [subnet mask guide](https://blog.biyongyao.com/network/ip-subnet-mask.html).

## Use Cases

- Network Administration: Quickly identify all devices on a network
- Security Auditing: Detect unauthorized devices
- IoT Management: Find and manage IoT devices on your network
- Troubleshooting: Verify network connectivity and device presence

## Contributing

Contributions are welcome! Here are some ways you can contribute:
- Enhance vendor name mapping.
- Improve scanning performance.
- Add new features.
- Fix bugs.

## todo

* Enhance the vendor name mapping 