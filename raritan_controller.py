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
    
    def execute_command(self, command: str) -> Tuple[str, str]:
        """Execute a command on the PDU and return stdout and stderr"""
        if not self._ssh_client or not self._ssh_client.get_transport() or not self._ssh_client.get_transport().is_active():
            if not self.connect():
                return "", f"Failed to connect to PDU {self.ip}"
        
        try:
            logger.debug(f"Executing command on PDU {self.ip}: {command}")
            stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=COMMAND_TIMEOUT)
            stdout_str = stdout.read().decode('utf-8')
            stderr_str = stderr.read().decode('utf-8')
            
            # Check for errors in Raritan's output
            # Some PDUs report errors in stdout rather than stderr
            if "Error:" in stdout_str:
                stderr_str += stdout_str
                stdout_str = ""
                
            logger.debug(f"Command response from PDU {self.ip}: {stdout_str}")
            if stderr_str:
                logger.warning(f"Command errors from PDU {self.ip}: {stderr_str}")
                
            return stdout_str, stderr_str
        
        except (SSHException, socket.error, socket.timeout) as e:
            logger.error(f"Error executing command on PDU {self.ip}: {e}")
            # Force disconnect to get fresh connection on next attempt
            self.disconnect()
            return "", str(e)

class ServerConfig:
    """Class representing a server with its outlets"""
    
    def __init__(self, name: str, bmc_ip: Optional[str] = None, outlets: Optional[List[Dict[str, Any]]] = None):
        self.name = name
        self.bmc_ip = bmc_ip
        self.outlets = outlets or []
        
    def __repr__(self) -> str:
        return f"ServerConfig(name={self.name}, bmc_ip={self.bmc_ip}, outlets={len(self.outlets)})"

class RaritanController:
    """Main controller class for Raritan PDUs"""
    
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.defaults = {}
        self.pdus: Dict[str, PDUConfig] = {}
        self.servers: Dict[str, ServerConfig] = {}
        
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from YAML file"""
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # Load defaults
            self.defaults = config.get('defaults', {})
            
            # Load PDUs
            for pdu_ip, pdu_config in config.get('pdus', {}).items():
                # Handle template variables in configuration
                username = self._process_template_var(pdu_config.get('username', ''), self.defaults)
                password = self._process_template_var(pdu_config.get('password', ''), self.defaults)
                port = int(self._process_template_var(pdu_config.get('port', 22), self.defaults))
                prompt = self._process_template_var(pdu_config.get('prompt', 'cli>'), self.defaults)
                
                self.pdus[pdu_ip] = PDUConfig(
                    ip=pdu_ip,
                    username=username,
                    password=password,
                    port=port,
                    prompt=prompt
                )
            
            # Load servers
            for server_name, server_config in config.get('servers', {}).items():
                outlets = server_config.get('outlets', [])
                self.servers[server_name] = ServerConfig(
                    name=server_name,
                    bmc_ip=server_config.get('bmc_ip'),
                    outlets=outlets
                )
                
            logger.info(f"Loaded {len(self.pdus)} PDUs and {len(self.servers)} servers from {self.config_file}")
            
        except (IOError, yaml.YAMLError) as e:
            logger.error(f"Error loading configuration from {self.config_file}: {e}")
            sys.exit(1)
    
    def _process_template_var(self, value: Any, defaults: Dict[str, Any]) -> Any:
        """Process template variables in configuration"""
        if isinstance(value, str) and value.startswith('#{defaults.'):
            var_name = value.split('.')[1].rstrip('}')
            return defaults.get(var_name, value)
        return value
    
    def get_server_config(self, server_name: str) -> Optional[ServerConfig]:
        """Get server configuration by name"""
        return self.servers.get(server_name)
    
    def get_pdu_config(self, pdu_ip: str) -> Optional[PDUConfig]:
        """Get PDU configuration by IP address"""
        return self.pdus.get(pdu_ip)
    
    def power_on_outlet(self, pdu_ip: str, outlet: int) -> bool:
        """Power on a specific outlet on a PDU"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return False
        
        command = f"set /system1/outlet{outlet} powerState=on"
        stdout, stderr = pdu.execute_command(command)
        
        if stderr:
            logger.error(f"Error powering on outlet {outlet} on PDU {pdu_ip}: {stderr}")
            return False
        
        logger.info(f"Powered on outlet {outlet} on PDU {pdu_ip}")
        return True
    
    def power_off_outlet(self, pdu_ip: str, outlet: int) -> bool:
        """Power off a specific outlet on a PDU"""
        pdu = self.get_pdu_config(pdu_ip)
        if not pdu:
            logger.error(f"No configuration found for PDU {pdu_ip}")
            return False
        
        command = f"set /system1/outlet{outlet} powerState=off"
        stdout, stderr = pdu.execute_command(command)
        
        if stderr:
            logger.error(f"Error powering off outlet {outlet} on PDU {pdu_ip}: {stderr}")
            return False
        
        logger.info(f"Powered off outlet {outlet} on PDU {pdu_ip}")
        return True
    
    def power_cycle_outlet(self, pdu_ip: str, outlet: int, delay: Optional[int] = None) -> bool:
        """Power cycle a specific outlet on a PDU"""
        delay = delay or self.defaults.get('power_on_delay', 5)
        
        # First power off
        if not self.power_off_outlet(pdu_ip, outlet):
            return False
        
        # Wait for the specified delay
        logger.info(f"Waiting {delay} seconds before powering on outlet {outlet} on PDU {pdu_ip}")
        time.sleep(delay)
        
        # Then power on
        return self.power_on_outlet(pdu_ip, outlet)
    
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
        """Perform a power operation on all outlets for a server"""
        server = self.get_server_config(server_name)
        if not server:
            logger.error(f"No configuration found for server {server_name}")
            return False
        
        if not server.outlets:
            logger.error(f"No outlets configured for server {server_name}")
            return False
        
        success = True
        # Track PDUs that have been used to avoid multiple connections
        used_pdus = set()
        
        try:
            # Process each outlet
            for outlet_config in server.outlets:
                pdu_ip = outlet_config['pdu']
                outlet = outlet_config['outlet']
                
                pdu = self.get_pdu_config(pdu_ip)
                if not pdu:
                    logger.error(f"No configuration found for PDU {pdu_ip}")
                    success = False
                    continue
                
                # Connect to PDU if not already connected
                if pdu_ip not in used_pdus:
                    if not pdu.connect():
                        logger.error(f"Failed to connect to PDU {pdu_ip}")
                        success = False
                        continue
                    used_pdus.add(pdu_ip)
                
                # Perform the requested operation
                result = False
                if operation == 'on':
                    result = self.power_on_outlet(pdu_ip, outlet)
                elif operation == 'off':
                    result = self.power_off_outlet(pdu_ip, outlet)
                elif operation == 'cycle':
                    result = self.power_cycle_outlet(pdu_ip, outlet)
                
                success = success and result
            
            return success
        
        finally:
            # Always disconnect from all used PDUs
            for pdu_ip in used_pdus:
                pdu = self.get_pdu_config(pdu_ip)
                if pdu:
                    pdu.disconnect()
    
    def get_server_outlet_status(self, server_name: str) -> Dict[str, Dict[int, str]]:
        """Get the status of all outlets for a server"""
        server = self.get_server_config(server_name)
        if not server:
            logger.error(f"No configuration found for server {server_name}")
            return {}
        
        if not server.outlets:
            logger.error(f"No outlets configured for server {server_name}")
            return {}
        
        results = {}
        # Track PDUs that have been used to avoid multiple connections
        used_pdus = set()
        
        try:
            for outlet_config in server.outlets:
                pdu_ip = outlet_config['pdu']
                outlet = outlet_config['outlet']
                
                pdu = self.get_pdu_config(pdu_ip)
                if not pdu:
                    logger.error(f"No configuration found for PDU {pdu_ip}")
                    continue
                
                # Connect to PDU if not already connected
                if pdu_ip not in used_pdus:
                    if not pdu.connect():
                        logger.error(f"Failed to connect to PDU {pdu_ip}")
                        continue
                    used_pdus.add(pdu_ip)
                
                # Initialize PDU results if not already done
                if pdu_ip not in results:
                    results[pdu_ip] = {}
                
                # Get status for this outlet
                status = self.get_outlet_status(pdu_ip, outlet)
                if status:
                    results[pdu_ip][outlet] = status
            
            return results
        
        finally:
            # Always disconnect from all used PDUs
            for pdu_ip in used_pdus:
                pdu = self.get_pdu_config(pdu_ip)
                if pdu:
                    pdu.disconnect()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Raritan PDU Controller')
    
    # Define commands
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # On command
    on_parser = subparsers.add_parser('on', help='Power on outlets')
    on_group = on_parser.add_mutually_exclusive_group(required=True)
    on_group.add_argument('server', nargs='?', help='Server name to power on')
    on_group.add_argument('--pdu', help='PDU IP address')
    on_parser.add_argument('--outlet', type=int, help='Outlet number (required with --pdu)')
    
    # Off command
    off_parser = subparsers.add_parser('off', help='Power off outlets')
    off_group = off_parser.add_mutually_exclusive_group(required=True)
    off_group.add_argument('server', nargs='?', help='Server name to power off')
    off_group.add_argument('--pdu', help='PDU IP address')
    off_parser.add_argument('--outlet', type=int, help='Outlet number (required with --pdu)')
    
    # Cycle command
    cycle_parser = subparsers.add_parser('cycle', help='Power cycle outlets')
    cycle_group = cycle_parser.add_mutually_exclusive_group(required=True)
    cycle_group.add_argument('server', nargs='?', help='Server name to power cycle')
    cycle_group.add_argument('--pdu', help='PDU IP address')
    cycle_parser.add_argument('--outlet', type=int, help='Outlet number (required with --pdu)')
    cycle_parser.add_argument('--delay', type=int, help='Delay in seconds between power off and power on')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check outlet status')
    status_group = status_parser.add_mutually_exclusive_group(required=True)
    status_group.add_argument('server', nargs='?', help='Server name to check status')
    status_group.add_argument('--pdu', help='PDU IP address')
    status_parser.add_argument('--outlet', type=int, help='Outlet number (optional with --pdu)')
    
    # Global options
    parser.add_argument('--config', default=CONFIG_FILE, help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.command is None:
        parser.print_help()
        sys.exit(1)
    
    if getattr(args, 'pdu', None) and args.command != 'status' and getattr(args, 'outlet', None) is None:
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
    """Main entry point"""
    args = parse_arguments()
    
    # Configure verbose logging if requested
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    controller = RaritanController(config_file=args.config)
    
    # Execute the requested command
    if args.command == 'on':
        if getattr(args, 'server', None):
            success = controller.operate_on_server(args.server, 'on')
            print(f"Power on {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_on_outlet(args.pdu, args.outlet)
            print(f"Power on {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    
    elif args.command == 'off':
        if getattr(args, 'server', None):
            success = controller.operate_on_server(args.server, 'off')
            print(f"Power off {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_off_outlet(args.pdu, args.outlet)
            print(f"Power off {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    
    elif args.command == 'cycle':
        if getattr(args, 'server', None):
            success = controller.operate_on_server(args.server, 'cycle')
            print(f"Power cycle {'successful' if success else 'failed'} for server {args.server}")
        else:
            success = controller.power_cycle_outlet(args.pdu, args.outlet, args.delay)
            print(f"Power cycle {'successful' if success else 'failed'} for outlet {args.outlet} on PDU {args.pdu}")
    
    elif args.command == 'status':
        if getattr(args, 'server', None):
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
                
                if getattr(args, 'outlet', None) is not None:
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