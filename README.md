# IP Enrichment Tool

## Overview
The IP Enrichment Tool is a Python-based utility designed for cybersecurity professionals, SOC analysts, and threat hunters to automate the enrichment of IP addresses with threat intelligence data. By integrating multiple open-source intelligence (OSINT) APIs, the tool provides context on IP addresses, helping users identify potential threats such as malicious scanning, malware distribution, or phishing infrastructure. This project is ideal for entry-level cybersecurity enthusiasts or freshers looking to build a portfolio project that demonstrates practical skills in API integration, data processing, and threat analysis.

The tool processes a list of IP addresses (via command-line or default list), validates them, queries APIs for enrichment, displays results in formatted tables, and exports data to JSON and CSV files. It also generates summary statistics for quick insights.

This project was inspired by real-world IP investigation workflows in security operations centers (SOCs) and is built to be modular, extensible, and beginner-friendly.

## Key Features

### Multi-API Integration:
- **AbuseIPDB:** Retrieves abuse confidence scores and country codes to assess IP reputation.
- **IPInfo:** Fetches ASN (Autonomous System Number), organization, and geolocation (city) details.
- **VirusTotal:** Checks for malicious detections and reputation scores linked to malware or phishing.
- **GreyNoise:** Determines IP classification (e.g., benign, malicious) and scanning activity (noise).

### Command-Line Interface (CLI):
Supports input of IPs via `--ips` flag for flexible usage.

### IP Validation:
Uses Python's `ipaddress` module to ensure only valid IPv4/IPv6 addresses are processed.

### Output Formats:
- Color-coded tables in the console using the `rich` library for readable results.
- Individual JSON files for each IP (e.g., `8.8.8.8_results.json`).
- A consolidated CSV file (`enrichment_results.csv`) for bulk analysis.

### Summary Statistics:
Displays a table summarizing total IPs processed and high-risk IPs (abuse confidence >= 50%).

### Error Handling:
Robust handling for API failures, rate limits, and invalid inputs, with clear logging.

### Secure API Key Management:
Uses environment variables via `.env` file to store keys securely (not committed to Git).

### Performance Tracking:
Measures and logs total execution time.

## Skills Demonstrated
This project showcases:
- **Python Programming:** API calls with `requests`, data parsing, and modular class-based design.
- **Cybersecurity Concepts:** Threat intelligence, IP reputation analysis, and OSINT tools.
- **Data Handling:** JSON/CSV export, validation with `ipaddress`, and summary aggregation.
- **CLI Development:** Argument parsing with `argparse`.
- **Visualization:** Formatted output with `rich`.
- **Best Practices:** Environment variables for secrets, error handling, and GitHub-friendly structure.

## Prerequisites

- **Python Version:** 3.8 or higher.
- **Dependencies:** Install via pip:

```bash
pip install requests rich python-dotenv tabulate
```

## API Keys (free tiers available):

- **AbuseIPDB:** Register at abuseipdb.com (1000 queries/day).
- **IPInfo:** Sign up at ipinfo.io (50,000 queries/month).
- **VirusTotal:** Create an account at virustotal.com (500 queries/day).
- **GreyNoise:** Get a Community API key at greynoise.io (rate-limited).

## Installation

### Clone the Repository:
```bash
git clone https://github.com/sadiq-95/IP-Enrichment-Python.git
cd IP-Enrichment-Python
```

### Set Up Virtual Environment (Recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install Dependencies:
```bash
pip install -r requirements.txt  # If requirements.txt exists, or use the pip command above
```

### Configure API Keys:
Create a `.env` file in the root directory with:
```env
ABUSEIPDB_API_KEY=your_abuseipdb_key
IPINFO_TOKEN=your_ipinfo_token
VIRUSTOTAL_API_KEY=your_virustotal_key
GREYNOISE_API_KEY=your_greynoise_key
```

The script loads these securely using `python-dotenv`.

## Usage
Run the script with default or custom IPs. The tool validates inputs, enriches data, and outputs results.

### Basic Command
Use default IPs (8.8.8.8, 1.1.1.1, 104.238.159.149):
```bash
python new.py
```

### Custom IPs
Provide IPs via CLI:
```bash
python new.py --ips 8.8.8.8 1.1.1.1 104.238.159.149
```

### Output Files
- **JSON Files:** One per IP (e.g., `8.8.8.8_results.json`).
- **CSV File:** `enrichment_results.csv` with all results.
- **Console:** Formatted tables and logs.

## Handling Errors
- **Invalid IPs:** Skipped with error logs.
- **API Failures:** "Error" in results; check logs for details (e.g., rate limits).

## Example Output
Here's a sample console output when enriching `8.8.8.8` and `1.1.1.1`:

```
Starting IP Enrichment Tool
[INFO] Starting enrichment for 8.8.8.8
[AbuseIPDB] 8.8.8.8 → Confidence: 0%, Country: US
[IPInfo] 8.8.8.8 → ASN: AS15169, Org: Google LLC, City: Mountain View
[VirusTotal] 8.8.8.8 → Malicious: 0, Reputation: Unknown
[GreyNoise] 8.8.8.8 → Classification: benign, Noise: False
╭──────────────────────────────────────────────────────────────────────────────╮
│ Enrichment for 8.8.8.8                                                      │
│ ┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ Source     ┃ Data                                                       ┃ │
│ ┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩ │
│ │ AbuseIPDB  │ Confidence Score: 0%, Country: US                          │ │
│ │ IPInfo     │ ASN: AS15169, Org: Google LLC, City: Mountain View         │ │
│ │ VirusTotal │ Malicious Detections: 0, Reputation: Unknown               │ │
│ │ GreyNoise  │ Classification: benign, Noise: False                       │ │
│ └────────────┴────────────────────────────────────────────────────────────┘ │
╰────────────────────────────────────────────────────────────────────────────╯
[INFO] Saved results for 8.8.8.8 to 8.8.8.8_results.json
[INFO] Starting enrichment for 1.1.1.1
[AbuseIPDB] 1.1.1.1 → Confidence: 0%, Country: AU
[IPInfo] 1.1.1.1 → ASN: AS13335, Org: Cloudflare, Inc., City: Brisbane
[VirusTotal] 1.1.1.1 → Malicious: 0, Reputation: Unknown
[GreyNoise] 1.1.1.1 → Classification: benign, Noise: False
╭──────────────────────────────────────────────────────────────────────────────╮
│ Enrichment for 1.1.1.1                                                      │
╰────────────────────────────────────────────────────────────────────────────╯
[INFO] Saved results for 1.1.1.1 to 1.1.1.1_results.json
[INFO] Saved all results to enrichment_results.csv
╭────────────────────────────────────────────────────────────╮
│ Summary Statistics                                         │
╰────────────────────────────────────────────────────────────╯
Enrichment complete in 2.12 seconds.
```

## JSON Example (`8.8.8.8_results.json`)
```json
{
    "AbuseIPDB": "Confidence Score: 0%, Country: US",
    "IPInfo": "ASN: AS15169, Org: Google LLC, City: Mountain View",
    "VirusTotal": "Malicious Detections: 0, Reputation: Unknown",
    "GreyNoise": "Classification: benign, Noise: False"
}
```

## CSV Example (`enrichment_results.csv`)
```
IP,AbuseIPDB,IPInfo,VirusTotal,GreyNoise
8.8.8.8,"Confidence Score: 0%, Country: US","ASN: AS15169, Org: Google LLC, City: Mountain View","Malicious Detections: 0, Reputation: Unknown","Classification: benign, Noise: False"
1.1.1.1,"Confidence Score: 0%, Country: AU","ASN: AS13335, Org: Cloudflare, Inc., City: Brisbane","Malicious Detections: 0, Reputation: Unknown","Classification: benign, Noise: False"
```

## Contributing
Contributions are welcome! To contribute:

1. Fork the repository.  
2. Create a feature branch (`git checkout -b feature/new-api`).  
3. Commit changes (`git commit -m "Add Shodan API integration"`).  
4. Push to the branch (`git push origin feature/new-api`).  
5. Open a Pull Request.

Please follow Python best practices and include tests if adding new features.

## Future Improvements
- Integrate additional APIs like Shodan for open port scanning or urlscan.io for URL analysis.  
- Add concurrent API calls using threading or `asyncio` for faster performance.  
- Support bulk input from CSV files or firewall logs.  
- Implement a web interface using Flask or Streamlit for non-CLI users.  
- Add unit tests with `pytest` for API responses and validation.  
- Enhance summary statistics with visualizations (e.g., using Matplotlib).

## License
This project is licensed under the **MIT License**. See the LICENSE file for details.

## Contact
**Author:** Sadiq-95 (Fresher in Cybersecurity)  
**GitHub:** sadiq-95  
**LinkedIn:** Your LinkedIn Profile  
**Email:** [your-email@example.com]

Feel free to reach out for feedback, collaborations, or job opportunities in cybersecurity! This project was built as part of my journey into threat intelligence and SOC operations.
