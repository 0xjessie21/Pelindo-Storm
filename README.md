[![Python 3.x](https://img.shields.io/badge/python-3.x-yellow.svg)](https://www.python.org/)

# Pelindo Amplification DDoS Tool
PelindoStorm is a DDoS (Distributed Denial of Service) tool designed to deliver amplification attacks via DNS, NTP, and Memcached protocols. This tool uses amplification techniques to magnify the effect of an attack by sending queries to public servers and utilizing a larger response than the request sent.

This tool is equipped with various advanced features such as Stealth Mode and Auto Resolver, which make it more effective in attacking targets while reducing the possibility of being detected by defense systems such as IDS/IPS.

# Screenshot
![Pelindo Storm](https://github.com/0xjessie21/Pelindo-Storm/blob/main/PStorm.png)

| :exclamation:  **Disclaimer**  |
|---------------------------------|
| This project is primarily built to be used as a standalone CLI tool. **Running this tool as a service may pose security risks.** It's recommended to use with caution and additional security measures. DWYOR |

## Overview of the tool
* Amplification Attacks
  - Supports DNS, NTP, and Memcached based attack methods.
  - Utilizes amplification techniques to increase traffic volume to the target.

* Stealth Mode
  - Hides attack patterns by randomizing delay times between packets.
  - Randomizes packet headers such as TTL, IP ID, and UDP source port to avoid detection.

* Auto Resolver
  - Automatically searches for the best domain for amplification.
  - No manual input required to select target domains.

* Custom Retry for Auto Resolver
  - Provides options to set the number of retries in domain searches to increase attack success.

# Installation
```sh
git clone https://github.com/username/PelindoStorm.git
cd PelindoStorm
pip3 install -r requirements.txt --break-system-packages
```

# Usage
```
sudo python3 pelindostorm.py
```
