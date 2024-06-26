# Command-Line Network Manager

## Overview
This command-line network manager is a Python program designed to manage network traffic.

## Features
- Sniff packets
- Scan for active hosts
- Send custom packets
- Perform SYN flood attacks
- download pcaps

## Dependencies
- scapy
- os

## Installation
1. Clone the repository:

    ```bash
    git clone https://github.com/27luket/cli-network-manager.git
    ```

2. Navigate into the cloned repository directory:

    ```bash
    cd cli-network-manager
    ```

3. Install dependencies:

    ```bash
    pip install -r dependencies.txt
    ```

## Usage
1. Run the program:

    ```bash
    sudo python cli_network_manager.py
    ```

2. Type `help` to see available commands.

3. Use commands like `start` to being sniffing, `stop` to stop sniffing, and `packet` to display the captured packets.


## Contributors
- Creator: [Luke Trujillo](https://github.com/27luket)
- Add-ons: [Luis Coronel](https://github.com/LuisCoronel2005)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
