# IOC Enrich

A simple Python CLI tool to read Indicators of Compromise (IOCs) from a file, detect their types (IP address, domain, MD5 hash), and prepare for enrichment via threat intelligence APIs.

## Features

- Reads IOCs (one per line) from a specified input file  
- Identifies IOC type using regex patterns: IPv4, domain names, MD5 hashes  
- Easy command-line interface using argparse  
- Modular design to extend with API enrichment (VirusTotal, AbuseIPDB, etc.)

## Getting Started

### Prerequisites

- Python 3.6+ installed  
- (Optional) API keys for enrichment services (coming soon!)

### Installation

1. Clone the repo:  
   ```bash
   git clone https://github.com/yourusername/ioc-enrich.git
   cd ioc-enrich
