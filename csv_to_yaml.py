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

def parse_pdu_names_and_ips(pdu_string: str) -> List[dict]:
    """Extract PDU names and IPs from the string (name=ip if no custom name)"""
    # Split on ' - ' or ' & ' or newlines
    pdu_entries = re.split(r'\s*[-&\n]\s*', pdu_string)
    result = []
    for entry in pdu_entries:
        entry = entry.strip()
        if not entry:
            continue
        # If entry is a URL, use the hostname as the name
        # Always try to extract an IP address
        ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', entry)
        ip = ip_match.group(1) if ip_match else ''
        if entry.startswith('http'):
            # Extract hostname for name
            match = re.search(r'https?://([^/]+)', entry)
            name = match.group(1) if match else entry
        else:
            name = entry
        result.append({'name': name, 'ip': ip})
    return result

def parse_outlet_numbers(outlet_string: str, num_pdus: int) -> List[List[int]]:
    """Distribute outlet numbers to PDUs in order. Returns a list of lists, one per PDU."""
    if not outlet_string or outlet_string == "":
        return [[] for _ in range(num_pdus)]
    outlets = [int(o.strip()) for o in re.findall(r'\d+', outlet_string)]
    # Distribute outlets as evenly as possible among PDUs
    result = [[] for _ in range(num_pdus)]
    for idx, outlet in enumerate(outlets):
        pdu_idx = idx % num_pdus
        result[pdu_idx].append(outlet)
    return result

# Custom representer to avoid quotes for outlet_number
class PlainStr(str): pass

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
                
                orig_server_name = row[0].strip()
                # Simplify server name: MGX-C2G2-XXX-<NUM> -> c2g2-<NUM>
                match = re.match(r"MGX-C2G2-[A-Z]+-(\d+)", orig_server_name)
                if match:
                    server_name = f"c2g2-{match.group(1)}"
                else:
                    server_name = orig_server_name
                bmc_ip = row[1].strip() if len(row) > 1 and row[1].strip() else None
                pdu_info = row[1].strip() if len(row) > 1 and row[1].strip() else None  # 2nd column is PDU address
                outlet_info = row[2].strip() if len(row) > 2 and row[2].strip() else None  # 3rd column is outlet
                
                if not server_name or server_name.startswith("system") or not pdu_info:
                    continue
                
                # Extract PDU names and IPs
                pdu_objs = parse_pdu_names_and_ips(pdu_info)
                if not pdu_objs:
                    continue
                
                # Add PDUs to config if not already present
                for pdu in pdu_objs:
                    if pdu['name'] not in config["pdus"]:
                        config["pdus"][pdu['name']] = {
                            "ip": pdu['ip']
                        }
                
                # Parse outlet information
                outlet_config = parse_outlet_numbers(outlet_info, len(pdu_objs))
                
                # If we have outlet information, create server entry
                if pdu_objs and (outlet_config or bmc_ip):
                    # Build outlets list: [{pdu_name: ..., outlet_number: ...}, ...]
                    outlets_list = []
                    for pdu_index, outlets in enumerate(outlet_config):
                        if pdu_index < len(pdu_objs):
                            pdu_name = pdu_objs[pdu_index]['name']
                            if outlets:
                                if len(outlets) == 1:
                                    outlet_number = outlets[0]
                                else:
                                    outlet_number = PlainStr(','.join(str(o) for o in outlets))
                                outlets_list.append({
                                    "pdu_name": pdu_name,
                                    "outlet_number": outlet_number
                                })
                    if outlets_list:
                        config["servers"][server_name] = [
                            {
                                "outlets": outlets_list
                            }
                        ]
    
    except Exception as e:
        print(f"Error processing CSV: {e}")
        raise
    
    return config

def main():
    """Main function to convert CSV to YAML"""
    try:
        config = create_config()
        
        # Custom representer to avoid quotes for outlet_number
        def plain_str_representer(dumper, data):
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='')
        yaml.add_representer(PlainStr, plain_str_representer)

        # Recursively convert all outlet_number values to PlainStr
        def convert_outlet_numbers(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == 'outlet_number':
                        obj[k] = PlainStr(v)
                    else:
                        convert_outlet_numbers(v)
            elif isinstance(obj, list):
                for item in obj:
                    convert_outlet_numbers(item)
        convert_outlet_numbers(config)

        with open(YAML_PATH, 'w', encoding='utf-8') as yaml_file:
            yaml.dump(config, yaml_file, default_flow_style=False, sort_keys=False)
        print(f"Configuration written to {YAML_PATH}")
    except Exception as e:
        print(f"Error creating config: {e}")

if __name__ == "__main__":
    main() 