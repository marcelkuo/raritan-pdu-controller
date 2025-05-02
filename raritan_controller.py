#!/usr/bin/env python3
"""
Raritan PDU Controller

This script provides power control for server outlets on Raritan PDUs via SSH.
It supports power on, power off, power cycle, and status operations.
"""

import argparse
import logging
import os
import re
import sys
import time
from typing import Dict, List, Optional, Union, Any, Tuple
import yaml
import paramiko
from paramiko.ssh_exception import SSHException, AuthenticationException
import socket
from prettytable import PrettyTable

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('raritan_controller')

# Constants
CONFIG_FILE = 'config.yaml'
MAX_RETRIES = 3
RETRY_DELAY = 2
CONNECTION_TIMEOUT = 10
COMMAND_TIMEOUT = 30

class PDUConfig:
    """Class representing a PDU configuration"""
    
    def __init__(self, ip: str, username: str, password: str, port: int = 22, prompt: str = 'cli>'):
        self.ip = ip
        self.username = username
        self.password = password
        self.port = port
        self.prompt = prompt
        self._ssh_client = None
        
    def __repr__(self) -> str:
        return f"PDUConfig(ip={self.ip}, username={self.username}, port={self.port})"
        
    @property
    def ssh_client(self) -> paramiko.SSHClient:
        """Return the SSH client, creating it if it doesn't exist"""
        if self._ssh_client is None:
            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return self._ssh_client
    
    def connect(self) -> bool:
        """Connect to the PDU via SSH"""
        for retry in range(MAX_RETRIES):
            try:
                logger.debug(f"Connecting to PDU {self.ip} (attempt {retry+1}/{MAX_RETRIES})")
                self.ssh_client.connect(
                    self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=CONNECTION_TIMEOUT,
                    look_for_keys=False,
                    allow_agent=False
                )
                logger.debug(f"Successfully connected to PDU {self.ip}")
                return True
            except (SSHException, AuthenticationException, socket.error) as e:
                logger.warning(f"Failed to connect to PDU {self.ip}: {e}")
                if retry < MAX_RETRIES - 1:
                    logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                else:
                    logger.error(f"Max retries exceeded, could not connect to PDU {self.ip}")
                    return False
        return False
    
    def disconnect(self) -> None:
        """Disconnect from the PDU"""
        if self._ssh_client is not None and self._ssh_client.get_transport() and self._ssh_client.get_transport().is_active():
            logger.debug(f"Disconnecting from PDU {self.ip}")
            self._ssh_client.close()
            self._ssh_client = None
    
    def _read_until_prompt(self, shell, prompt: str, timeout: int) -> str:
        """Read from the shell until the prompt is seen or timeout occurs. Returns the full buffer."""
        output = ""
        start_time = time.time()
        while True:
            if shell.recv_ready():
                try:
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    output += chunk
                    logger.debug(f"[SHELL READ] {chunk!r}")
                except Exception as e:
                    logger.error(f"Error reading from shell: {e}")
                    break
                if prompt in output:
                    break
            if time.time() - start_time > timeout:
                logger.error(f"Timeout waiting for prompt '{prompt}'. Buffer so far:\n{output}")
                break
            time.sleep(0.1)
        return output

    def _read_until_banner(self, shell, banner_regex: str, timeout: int) -> str:
        output = ""
        start_time = time.time()
        while True:
            if shell.recv_ready():
                try:
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    output += chunk
                    logger.debug(f"[SHELL READ] {chunk!r}")
                    if re.search(banner_regex, output):
                        break
                except Exception as e:
                    logger.error(f"Error reading from shell: {e}")
                    break
            if time.time() - start_time > timeout:
                logger.error(f"Timeout waiting for banner. Buffer so far:\\n{output}")
                break
            time.sleep(0.1)
        return output

    def execute_command(self, command: str) -> Tuple[str, str]:
        """Execute a command on the PDU using an interactive shell and return stdout and stderr, with robust debug logging."""
        if not self._ssh_client or not self._ssh_client.get_transport() or not self._ssh_client.get_transport().is_active():
            if not self.connect():
                return "", f"Failed to connect to PDU {self.ip}"
        try:
            logger.debug(f"Preparing to execute command on PDU {self.ip}: {command}")
            shell = self._ssh_client.invoke_shell()
            shell.settimeout(COMMAND_TIMEOUT)
            prompt = self.prompt
            banner_regex = r"Welcome to .+ CLI!"
            shell.send("\n")
            # Wait for the banner
            initial_output = self._read_until_banner(shell, banner_regex, 5)
            if not re.search(banner_regex, initial_output):
                return "", f"Timeout waiting for welcome banner. Buffer:\n{initial_output}"
            
            # Wait 1 second, then check for prompt
            time.sleep(1)
            
            # Read a bit more to get the full prompt
            additional_output = ""
            start_time = time.time()
            while time.time() - start_time < 3:  # Read for up to 3 more seconds
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='replace')
                    additional_output += chunk
                    logger.debug(f"[SHELL READ] {chunk!r}")
                time.sleep(0.1)
            
            full_output = initial_output + additional_output
            
            # Try to detect the actual prompt automatically
            prompt_match = re.search(r'\r\n(.+?)(\s*>|\s*#)\s*$', full_output)
            if prompt_match:
                detected_prompt = prompt_match.group(0).strip()
                if detected_prompt and prompt != detected_prompt:
                    logger.debug(f"Detected different prompt: '{detected_prompt}', was using: '{prompt}'")
                    prompt = detected_prompt
            
            if prompt not in full_output:
                # Read until prompt appears (shorter timeout)
                prompt_output = self._read_until_prompt(shell, prompt, 10)
                full_output += prompt_output
                if prompt not in full_output:
                    return "", f"Timeout waiting for prompt after banner. Buffer:\n{full_output}"
            
            # Now send the command
            logger.debug(f"Executing command on PDU {self.ip}: {command}")
            shell.send(command + "\n")
            cmd_output = self._read_until_prompt(shell, prompt, COMMAND_TIMEOUT)
            if prompt not in cmd_output:
                return "", f"Timeout waiting for command prompt. Buffer:\n{cmd_output}"
            
            # Remove echoed command and prompt from output
            lines = cmd_output.splitlines()
            for i, line in enumerate(lines[:2]):
                if command.strip() == line.strip():
                    lines = lines[i+1:]
                    break
            while lines and prompt.strip() in lines[-1]:
                lines = lines[:-1]
            output = "\n".join(lines)
            return output, ""
        except Exception as e:
            logger.error(f"Error executing command on PDU {self.ip}: {e}")
            self.disconnect()
            return "", str(e)

class ServerConfig:
    """Class representing a server with its outlets (new YAML format)"""
    def __init__(self, name: str, outlets: Optional[list] = None):
        self.name = name
        self.outlets = outlets or []
    def __repr__(self) -> str:
        return f"ServerConfig(name={self.name}, outlets={len(self.outlets)})"

class RaritanController:
    """Main controller class for Raritan PDUs"""
    
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.defaults = {}
        self.pdus: Dict[str, PDUConfig] = {}
        self.servers: Dict[str, ServerConfig] = {}
        self.server_name_map: Dict[str, str] = {}  # Map original hostname to simplified name
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file (adapted for new format)"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
            self.defaults = config.get('defaults', {})
            for pdu_name, pdu_config in config.get('pdus', {}).items():
                username = self._process_template_var(pdu_config.get('username', ''), self.defaults, 'username')
                password = self._process_template_var(pdu_config.get('password', ''), self.defaults, 'password')
                port = int(self._process_template_var(pdu_config.get('port', 22), self.defaults, 'port'))
                prompt = self._process_template_var(pdu_config.get('prompt', 'cli>'), self.defaults, 'prompt')
                # Use the actual IP address from the pdu_config for connection
                self.pdus[pdu_name] = PDUConfig(
                    ip=pdu_config.get('ip', pdu_name),
                    username=username,
                    password=password,
                    port=port,
                    prompt=prompt
                )
            # Load servers (new format)
            for server_name, server_list in config.get('servers', {}).items():
                if not isinstance(server_list, list) or not server_list:
                    continue
                server_entry = server_list[0]
                outlets = server_entry.get('outlets', [])
                # Try to recover the original hostname if present in the outlets or elsewhere
                # If the original name is different from the simplified name, store the mapping
                orig_name = server_entry.get('orig_name', None)
                if orig_name and orig_name != server_name:
                    self.server_name_map[orig_name] = server_name
                self.servers[server_name] = ServerConfig(
                    name=server_name,
                    outlets=outlets
                )
            logger.info(f"Loaded {len(self.pdus)} PDUs and {len(self.servers)} servers from {self.config_file}")
        except (IOError, yaml.YAMLError) as e:
            logger.error(f"Error loading configuration from {self.config_file}: {e}")
            sys.exit(1)
    
    def _process_template_var(self, value: Any, defaults: Dict[str, Any], key: str = None) -> Any:
        """Process template variables in configuration, and use default if value is missing or empty"""
        if isinstance(value, str) and value.startswith('#{defaults.'):
            var_name = value.split('.')[1].rstrip('}')
            return defaults.get(var_name, value)
        # If value is None or empty string, use the default for this key
        if (value is None or value == '') and key is not None and key in defaults:
            return defaults[key]
        return value
    
    def get_server_config(self, server_name: str) -> Optional[ServerConfig]:
        """Get server configuration by name, supporting both original and simplified names"""
        if server_name in self.servers:
            return self.servers[server_name]
        # Try mapping from original hostname to simplified name
        mapped = self.server_name_map.get(server_name)
        if mapped and mapped in self.servers:
            return self.servers[mapped]
        return None
    
    def get_pdu_config(self, pdu_ip: str) -> Optional[PDUConfig]:
        """Get PDU configuration by IP address"""
        return self.pdus.get(pdu_ip)
    
    def power_on_outlet(self, pdu_ip: str, outlets: Union[int, list]) -> bool:
        """Power on one or more outlets on a PDU (new command format)"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return False
        if isinstance(outlets, int):
            outlet_list = [outlets]
        else:
            outlet_list = outlets
        outlet_str = ','.join(str(o) for o in outlet_list)
        command = f"power outlets {outlet_str} on /y"
        stdout, stderr = pdu.execute_command(command)
        if stderr:
            logger.error(f"Error powering on outlet(s) {outlet_str} on PDU {pdu_ip}: {stderr}")
            return False
        logger.info(f"Powered on outlet(s) {outlet_str} on PDU {pdu_ip}")
        return True

    def power_off_outlet(self, pdu_ip: str, outlets: Union[int, list]) -> bool:
        """Power off one or more outlets on a PDU (new command format)"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return False
        if isinstance(outlets, int):
            outlet_list = [outlets]
        else:
            outlet_list = outlets
        outlet_str = ','.join(str(o) for o in outlet_list)
        command = f"power outlets {outlet_str} off /y"
        stdout, stderr = pdu.execute_command(command)
        if stderr:
            logger.error(f"Error powering off outlet(s) {outlet_str} on PDU {pdu_ip}: {stderr}")
            return False
        logger.info(f"Powered off outlet(s) {outlet_str} on PDU {pdu_ip}")
        return True

    def power_cycle_outlet(self, pdu_ip: str, outlets: Union[int, list], delay: Optional[int] = None) -> bool:
        """Power cycle one or more outlets on a PDU (new command format)"""
        delay = delay or self.defaults.get('power_on_delay', 5)
        if isinstance(outlets, int):
            outlet_list = [outlets]
        else:
            outlet_list = outlets
        outlet_str = ','.join(str(o) for o in outlet_list)
        # Power off
        if not self.power_off_outlet(pdu_ip, outlet_list):
            return False
        logger.info(f"Waiting {delay} seconds before powering on outlet(s) {outlet_str} on PDU {pdu_ip}")
        time.sleep(delay)
        # Power on
        return self.power_on_outlet(pdu_ip, outlet_list)
    
    def get_outlet_status(self, pdu_ip: str, outlet: int) -> Optional[str]:
        """Get the status of a specific outlet on a PDU"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return None
        
        command = f"show /system1/outlet{outlet}"
        stdout, stderr = pdu.execute_command(command)
        
        if stderr:
            logger.error(f"Error getting status for outlet {outlet} on PDU {pdu_ip}: {stderr}")
            return None
        
        # Parse the status from the output
        match = re.search(r'powerState\s*=\s*([^\s,]+)', stdout)
        if match:
            return match.group(1)
        
        logger.warning(f"Could not parse status for outlet {outlet} on PDU {pdu_ip}")
        return None
    
    def get_all_pdu_outlet_status(self, pdu_ip: str) -> Dict[int, str]:
        """Get the status of all outlets on a PDU"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return {}
        
        command = "show /system1/outlets"
        stdout, stderr = pdu.execute_command(command)
        
        if stderr:
            logger.error(f"Error getting status for outlets on PDU {pdu_ip}: {stderr}")
            return {}
        
        results = {}
        # Parse status for each outlet
        outlet_pattern = r'/system1/outlet(\d+)\s+.*powerState=([^\s,]+)'
        for match in re.finditer(outlet_pattern, stdout):
            outlet = int(match.group(1))
            status = match.group(2)
            results[outlet] = status
        
        return results
    
    def operate_on_server(self, server_name: str, operation: str) -> bool:
        """Perform a power operation on all outlets for a server (new YAML format, new command format)"""
        server = self.get_server_config(server_name)
        if not server:
            logger.error(f"No configuration found for server {server_name}")
            return False
        if not server.outlets:
            logger.error(f"No outlets configured for server {server_name}")
            return False
        success = True
        used_pdus = set()
        try:
            # Group outlets by PDU for batch command
            pdu_outlet_map = {}
            for outlet_config in server.outlets:
                pdu_ip = outlet_config['pdu_name']
                outlet_number = outlet_config['outlet_number']
                if isinstance(outlet_number, int):
                    outlet_numbers = [outlet_number]
                elif isinstance(outlet_number, str):
                    outlet_numbers = [int(x.strip()) for x in outlet_number.split(',') if x.strip()]
                else:
                    continue
                if pdu_ip not in pdu_outlet_map:
                    pdu_outlet_map[pdu_ip] = []
                pdu_outlet_map[pdu_ip].extend(outlet_numbers)
            for pdu_ip, outlet_list in pdu_outlet_map.items():
                pdu = self.get_pdu_config(pdu_ip)
                if not pdu:
                    logger.error(f"No configuration found for PDU {pdu_ip}")
                    success = False
                    continue
                if pdu_ip not in used_pdus:
                    if not pdu.connect():
                        logger.error(f"Failed to connect to PDU {pdu_ip}")
                        success = False
                        continue
                    used_pdus.add(pdu_ip)
                result = False
                if operation == 'on':
                    result = self.power_on_outlet(pdu_ip, outlet_list)
                elif operation == 'off':
                    result = self.power_off_outlet(pdu_ip, outlet_list)
                elif operation == 'cycle':
                    result = self.power_cycle_outlet(pdu_ip, outlet_list)
                success = success and result
            return success
        finally:
            for pdu_ip in used_pdus:
                pdu = self.get_pdu_config(pdu_ip)
                if pdu:
                    pdu.disconnect()
    
    def get_server_outlet_status(self, server_name: str) -> Dict[str, Dict[int, str]]:
        """Get the status of all outlets for a server (new YAML format)"""
        server = self.get_server_config(server_name)
        if not server:
            logger.error(f"No configuration found for server {server_name}")
            return {}
        if not server.outlets:
            logger.error(f"No outlets configured for server {server_name}")
            return {}
        results = {}
        used_pdus = set()
        try:
            for outlet_config in server.outlets:
                pdu_ip = outlet_config['pdu_name']
                outlet_number = outlet_config['outlet_number']
                if isinstance(outlet_number, int):
                    outlet_numbers = [outlet_number]
                elif isinstance(outlet_number, str):
                    outlet_numbers = [int(x.strip()) for x in outlet_number.split(',') if x.strip()]
                else:
                    continue
                pdu = self.get_pdu_config(pdu_ip)
                if not pdu:
                    logger.error(f"No configuration found for PDU {pdu_ip}")
                    continue
                if pdu_ip not in used_pdus:
                    if not pdu.connect():
                        logger.error(f"Failed to connect to PDU {pdu_ip}")
                        continue
                    used_pdus.add(pdu_ip)
                if pdu_ip not in results:
                    results[pdu_ip] = {}
                for outlet in outlet_numbers:
                    status = self.get_outlet_status(pdu_ip, outlet)
                    if status:
                        results[pdu_ip][outlet] = status
            return results
        finally:
            for pdu_ip in used_pdus:
                pdu = self.get_pdu_config(pdu_ip)
                if pdu:
                    pdu.disconnect()

def parse_arguments():
    """Parse command line arguments (server first, command last)"""
    parser = argparse.ArgumentParser(description='Raritan PDU Controller (server first, command last)')
    parser.add_argument('server', nargs='?', help='Server name to operate on (or leave blank if using --pdu)')
    parser.add_argument('--pdu', help='PDU IP address')
    parser.add_argument('--outlet', type=int, help='Outlet number (required with --pdu)')
    parser.add_argument('--delay', type=int, help='Delay in seconds between power off and power on (for cycle)')
    parser.add_argument('--config', default=CONFIG_FILE, help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('command', choices=['on', 'off', 'cycle', 'status'], help='Power command to execute')
    args = parser.parse_args()
    # Validate arguments
    if not args.server and not args.pdu:
        parser.error('You must specify either a server name or --pdu')
    if args.pdu and args.command != 'status' and args.outlet is None:
        parser.error('--outlet is required when specifying --pdu (except with status command)')
    return args

def format_status_table(results: Dict[str, Dict[int, str]], server_name: Optional[str] = None) -> str:
    """Format status results as a pretty table"""
    table = PrettyTable()
    table.field_names = ["PDU IP", "Outlet", "Status", "Server"]
    
    for pdu_ip, outlets in results.items():
        for outlet, status in sorted(outlets.items()):
            table.add_row([pdu_ip, outlet, status, server_name or ""])
    
    return table.get_string()

def main():
    """Main entry point (server first, command last)"""
    args = parse_arguments()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    controller = RaritanController(config_file=args.config)
    # Execute the requested command
    if args.command == 'on':
        if args.server:
            success = controller.operate_on_server(args.server, 'on')
            print(f"Power on {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_on_outlet(args.pdu, args.outlet)
            print(f"Power on {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    elif args.command == 'off':
        if args.server:
            success = controller.operate_on_server(args.server, 'off')
            print(f"Power off {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_off_outlet(args.pdu, args.outlet)
            print(f"Power off {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    elif args.command == 'cycle':
        if args.server:
            success = controller.operate_on_server(args.server, 'cycle')
            print(f"Power cycle {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_cycle_outlet(args.pdu, args.outlet, args.delay)
            print(f"Power cycle {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    elif args.command == 'status':
        if args.server:
            results = controller.get_server_outlet_status(args.server)
            print(format_status_table(results, args.server))
        else:
            pdu = controller.get_pdu_config(args.pdu)
            if not pdu:
                logger.error(f"No configuration found for PDU {args.pdu}")
                sys.exit(1)
            try:
                if not pdu.connect():
                    logger.error(f"Failed to connect to PDU {args.pdu}")
                    sys.exit(1)
                if args.outlet is not None:
                    status = controller.get_outlet_status(args.pdu, args.outlet)
                    results = {args.pdu: {args.outlet: status}} if status else {}
                else:
                    status_dict = controller.get_all_pdu_outlet_status(args.pdu)
                    results = {args.pdu: status_dict}
                print(format_status_table(results))
            finally:
                pdu.disconnect()

if __name__ == '__main__':
    main()