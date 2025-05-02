# Raritan PDU Controller

This tool allows you to control Raritan PDUs (Power Distribution Units) via SSH to manage power for multiple servers.

## Features

- Control multiple outlets across multiple PDUs
- Supports power on, power off, power cycle, and status check operations
- Server-based or outlet-based operations
- Configuration via YAML file with support for global defaults
- Secure SSH connection handling

## Configuration

The tool uses a YAML configuration file (`config.yaml`) that defines:

1. Global defaults (username, password, SSH port, etc.)
2. PDU configurations
3. Server configurations with associated PDU outlets

Example structure:

```yaml
defaults:
  username: admin
  password: password
  port: 22
  prompt: cli>
  power_on_delay: 5

pdus:
  10.0.0.1:
    ip: 10.0.0.1
    username: #{defaults.username}
    password: #{defaults.password}
    port: #{defaults.port}
    prompt: #{defaults.prompt}

servers:
  server1:
    name: server1
    bmc_ip: 10.1.1.1
    outlets:
      - pdu: 10.0.0.1
        outlet: 1
      - pdu: 10.0.0.1
        outlet: 2
```

### Security Note

For security reasons, the actual `config.yaml` file is excluded from version control in the `.gitignore` file. A sample configuration file named `config.sample.yaml` is provided as a template. To set up your configuration:

1. Copy `config.sample.yaml` to `config.yaml`
2. Edit `config.yaml` to add your actual PDU credentials and configuration
3. Never commit `config.yaml` to version control

## Installation

1. Ensure you have Python 3.7+ installed
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Create your configuration file as described above

## Usage

```bash
# Power on all outlets for a server
python raritan_controller.py on server_name

# Power off all outlets for a server
python raritan_controller.py off server_name

# Power cycle all outlets for a server
python raritan_controller.py cycle server_name

# Check status of all outlets for a server
python raritan_controller.py status server_name

# Control specific outlet on a PDU
python raritan_controller.py on --pdu 10.0.0.1 --outlet 5

# Check status of all outlets on a PDU
python raritan_controller.py status --pdu 10.0.0.1
```

## CSV to YAML Conversion

The repository includes a utility to convert server and PDU information from a CSV file to the YAML configuration format:

```bash
python csv_to_yaml.py
```

This will read `server_pdu_list.csv` and generate a properly formatted `config.yaml` file. Please review and update any sensitive information in the generated file.

## Requirements

- Python 3.7+
- Paramiko (SSH library)
- PyYAML
- Pandas (for CSV conversion)
- PrettyTable (for status display)