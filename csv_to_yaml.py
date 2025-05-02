#!/usr/bin/env python3
"""
Convert server_pdu_list.csv to config.yaml for Raritan PDU controller
"""

import csv
import yaml
import re
import os
import pandas as pd
from typing import Dict, List, Any, Optional

# Define the path to the input CSV and output YAML
CSV_PATH = "server_pdu_list.csv"
YAML_PATH = "config.yaml"

def parse_pdu_ips(pdu_string: str) -> List[str]:
    """Extract PDU IP addresses from the string"""
    # Look for IP addresses in the string
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, pdu_string)
    return ips

def parse_outlet_numbers(outlet_string: str) -> List[Dict[str, List[int]]]:
    """Extract outlet numbers from the string"""
    if not outlet_string or outlet_string == "":
        return []
    
    result = []
    
    # Check if there are multiple PDUs with different outlets
    if 'A' in outlet_string and 'B' in outlet_string:
        # Format like "6,20 A \n2,20 B"
        sections = re.split(r'\s*[AB]\s*', outlet_string)
        sections = [s.strip() for s in sections if s.strip()]
        
        if len(sections) >= 2:
            # First section is for PDU A
            a_outlets = [int(o.strip()) for o in re.findall(r'\d+', sections[0])]
            # Second section is for PDU B
            b_outlets = [int(o.strip()) for o in re.findall(r'\d+', sections[1])]
            
            if a_outlets:
                result.append({"pdu_index": 0, "outlets": a_outlets})
            if b_outlets:
                result.append({"pdu_index": 1, "outlets": b_outlets})
    else:
        # Simple format like "13,5" or "30,31"
        outlets = [int(o.strip()) for o in re.findall(r'\d+', outlet_string)]
        if outlets:
            # Assume first PDU if not specified
            result.append({"pdu_index": 0, "outlets": outlets})
    
    return result

def create_config() -> Dict[str, Any]:
    """Create the configuration dictionary from CSV data"""
    config = {
        "defaults": {
            "username": "colossushosted",
            "password": "YOUR_PASSWORD_HERE",  # Password placeholder
            "port": 22,
            "prompt": "cli>",
            "power_on_delay": 5
        },
        "pdus": {},
        "servers": {}
    }
    
    try:
        with open(CSV_PATH, 'r', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            # Skip header rows
            for _ in range(2):
                next(reader)
            
            # Process each row
            for row in reader:
                if not row or not row[0]:  # Skip empty rows
                    continue
                
                server_name = row[0].strip()
                bmc_ip = row[1].strip() if len(row) > 1 and row[1].strip() else None
                pdu_info = row[2].strip() if len(row) > 2 and row[2].strip() else None
                outlet_info = row[3].strip() if len(row) > 3 and row[3].strip() else None
                
                if not server_name or server_name.startswith("system") or not pdu_info:
                    continue
                
                # Extract PDU IPs
                pdu_ips = parse_pdu_ips(pdu_info)
                if not pdu_ips:
                    continue
                
                # Add PDUs to config if not already present
                for i, pdu_ip in enumerate(pdu_ips):
                    if pdu_ip not in config["pdus"]:
                        config["pdus"][pdu_ip] = {
                            "ip": pdu_ip,
                            # Use defaults for these values
                            "username": "#{defaults.username}",
                            "password": "#{defaults.password}",
                            "port": "#{defaults.port}",
                            "prompt": "#{defaults.prompt}"
                        }
                
                # Parse outlet information
                outlet_config = parse_outlet_numbers(outlet_info)
                
                # If we have outlet information, create server entry
                if pdu_ips and (outlet_config or bmc_ip):
                    config["servers"][server_name] = {
                        "name": server_name
                    }
                    
                    if bmc_ip:
                        config["servers"][server_name]["bmc_ip"] = bmc_ip
                    
                    # Add outlet information if available
                    if outlet_config:
                        outlet_list = []
                        for oc in outlet_config:
                            pdu_index = oc["pdu_index"]
                            if pdu_index < len(pdu_ips):
                                for outlet in oc["outlets"]:
                                    outlet_list.append({
                                        "pdu": pdu_ips[pdu_index],
                                        "outlet": outlet
                                    })
                        
                        if outlet_list:
                            config["servers"][server_name]["outlets"] = outlet_list
    
    except Exception as e:
        print(f"Error processing CSV: {e}")
        raise
    
    return config

def main():
    """Main function to convert CSV to YAML"""
    try:
        config = create_config()
        
        # Write to YAML file
        with open(YAML_PATH, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(config, yaml_file, default_flow_style=False, sort_keys=False)
        
        print(f"Configuration written to {YAML_PATH}")
    except Exception as e:
        print(f"Error creating config: {e}")

if __name__ == "__main__":
    main() 