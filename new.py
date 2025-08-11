import requests
import time
import argparse
import json
import ipaddress
import csv
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Initialize rich console for formatted output
console = Console()

# API keys (replace with your own keys)
ABUSEIPDB_API_KEY = "5d8d5b1dc0340093c330e09b65b7fd75e250e2b2fbc6aa08c34220ff2b00066693cce2fb0f1d346c"  # Get from abuseipdb.com
IPINFO_TOKEN = "fc82db3e57f44c"  # Get from ipinfo.io
VIRUSTOTAL_API_KEY = "59fa745639b8cc22e0e65e0319de420779553b1ffba2888a3e8d5ed7e6d8c452"  # Get from virustotal.com
GREYNOISE_API_KEY = "CSwfcuJJBOuT12txAigJTWyDzu2xVgiSwdEA6zX4hX8XnBlgXloVlJZqjA1CY2fS"  # Get from greynoise.io

# List of IPs to enrich (default for testing)
default_ip_list = ["8.8.8.8", "1.1.1.1", "104.238.159.149"]

class IPEnricher:
    def __init__(self, ip):
        self.ip = ip
        self.result = {}

    def abuseipdb(self):
        """Fetch abuse confidence score and country from AbuseIPDB."""
        url = f"https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": self.ip, "maxAgeInDays": 90}
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            confidence = data["data"]["abuseConfidenceScore"]
            country = data["data"]["countryCode"] or "Unknown"
            self.result["AbuseIPDB"] = f"Confidence Score: {confidence}%, Country: {country}"
            console.log(f"[green][AbuseIPDB][/green] {self.ip} → Confidence: {confidence}%, Country: {country}")
        except requests.RequestException as e:
            self.result["AbuseIPDB"] = "Error"
            console.log(f"[red][AbuseIPDB][/red] {self.ip} → Failed: {e}")

    def ipinfo(self):
        """Fetch ASN, organization, and city from IPInfo."""
        url = f"https://ipinfo.io/{self.ip}/json"
        params = {"token": IPINFO_TOKEN}
        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            asn = data.get("asn", "Unknown")
            org = data.get("org", "Unknown")
            city = data.get("city", "Unknown")
            self.result["IPInfo"] = f"ASN: {asn}, Org: {org}, City: {city}"
            console.log(f"[green][IPInfo][/green] {self.ip} → ASN: {asn}, Org: {org}, City: {city}")
        except requests.RequestException as e:
            self.result["IPInfo"] = "Error"
            console.log(f"[red][IPInfo][/red] {self.ip} → Failed: {e}")
    def virustotal(self):
        """Fetch malicious activity data from VirusTotal."""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            reputation = data["data"]["attributes"].get("reputation", "Unknown")
            self.result["VirusTotal"] = f"Malicious Detections: {malicious}, Reputation: {reputation}"
            console.log(f"[green][VirusTotal][/green] {self.ip} → Malicious: {malicious}, Reputation: {reputation}")
        except requests.RequestException as e:
            self.result["VirusTotal"] = "Error"
            console.log(f"[red][VirusTotal][/red] {self.ip} → Failed: {e}")

    def greynoise(self):
        """Fetch scanning activity from GreyNoise Community API."""
        url = f"https://api.greynoise.io/v3/community/{self.ip}"
        headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            classification = data.get("classification", "Unknown")
            noise = data.get("noise", False)
            self.result["GreyNoise"] = f"Classification: {classification}, Noise: {noise}"
            console.log(f"[green][GreyNoise][/green] {self.ip} → Classification: {classification}, Noise: {noise}")
        except requests.RequestException as e:
            self.result["GreyNoise"] = "Error"
            console.log(f"[red][GreyNoise][/red] {self.ip} → Failed: {e}")


    def enrich(self):
        """Run enrichment for all data sources."""
        self.abuseipdb()
        self.ipinfo()
        self.virustotal()
        self.greynoise()

    def display_result(self):
        """Display results in a formatted table and save to JSON."""
        table = Table(title=f"Enrichment for {self.ip}", show_lines=True)
        table.add_column("Source", style="bold cyan")
        table.add_column("Data", style="bold yellow")

        for key, value in self.result.items():
            table.add_row(key, str(value))

        console.print(Panel(table, border_style="green"))

        # Save results to JSON
        try:
            with open(f"{self.ip}_results.json", "w") as f:
                json.dump(self.result, f, indent=4)
            console.log(f"[blue][INFO][/blue] Saved results for {self.ip} to {self.ip}_results.json")
        except Exception as e:
            console.log(f"[red][ERROR][/red] Failed to save JSON for {self.ip}: {e}")

def validate_ip(ip):
    """Validate if the input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        console.log(f"[red][ERROR][/red] Invalid IP address: {ip}")
        return False

def main():
    """Main function to process IP list and display results."""
    parser = argparse.ArgumentParser(description="IP Enrichment Tool")
    parser.add_argument("--ips", nargs="+", help="List of IPs to enrich")
    args = parser.parse_args()
    ip_list = args.ips if args.ips else default_ip_list

    # Validate IPs
    valid_ips = [ip for ip in ip_list if validate_ip(ip)]
    if not valid_ips:
        console.print("[red][ERROR][/red] No valid IPs provided. Exiting.")
        return

    # Store results for CSV
    all_results = []

    start_time = time.time()
    console.print("[bold blue]Starting IP Enrichment Tool[/bold blue]")

    for ip in valid_ips:
        console.log(f"[blue][INFO][/blue] Starting enrichment for {ip}")
        enricher = IPEnricher(ip)
        enricher.enrich()
        enricher.display_result()
        all_results.append({"IP": ip, "AbuseIPDB": enricher.result.get("AbuseIPDB", "Error"), "IPInfo": enricher.result.get("IPInfo", "Error")})

    # Save to CSV
    try:
        with open("enrichment_results.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["IP", "AbuseIPDB", "IPInfo"])
            writer.writeheader()
            writer.writerows(all_results)
        console.log(f"[blue][INFO][/blue] Saved all results to enrichment_results.csv")
    except Exception as e:
        console.log(f"[red][ERROR][/red] Failed to save CSV: {e}")

    end_time = time.time()
    console.print(f"[bold green]Enrichment complete in {round(end_time - start_time, 2)} seconds.[/bold green]")

if __name__ == "__main__":
    main()