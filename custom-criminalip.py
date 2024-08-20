#!/usr/bin/env python
# Shahidahktar@gmail.com
# Developed by Shahid Akhter
import sys
import os
import json
import ipaddress
import requests
from requests.exceptions import ConnectionError, HTTPError
from socket import socket, AF_UNIX, SOCK_DGRAM
import time

# Enable or disable debugging
debug_enabled = True  # Set to False to disable debug logging

# File and socket paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f'{pwd}/queue/sockets/queue'

# Set paths for logging
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = f'{pwd}/logs/integrations.log'


def debug(msg):
    """Log debug messages."""
    if debug_enabled:
        timestamped_msg = f"{now}: {msg}\n"
        print(timestamped_msg)
        with open(log_file, "a") as f:
            f.write(timestamped_msg)


def send_event(msg, agent=None):
    """Send an event to the Wazuh Manager."""
    try:
        if not agent or agent["id"] == "000":
            string = f'1:criminalip:{json.dumps(msg)}'
        else:
            string = f'1:[{agent["id"]}] ({agent["name"]}) {agent["ip"] if "ip" in agent else "any"}->criminalip:{json.dumps(msg)}'
        
        debug(f"Sending Event: {string}")
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(socket_addr)
            sock.send(string.encode())
    except Exception as e:
        debug(f"Error sending event: {e}")


# Read configuration parameters
try:
    alert_file = open(sys.argv[1])
    alert = json.loads(alert_file.read())
    alert_file.close()
    debug("Alert loaded successfully")
except Exception as e:
    debug(f"Error reading alert file: {e}")
    sys.exit(1)

# New Alert Output for CriminalIP Alert or Error calling the API
alert_output = {}

# CriminalIP API AUTH KEY
criminalip_api_key = api_key

# API - HTTP Headers
criminalip_apicall_headers = {
    "x-api-key": f"{criminalip_api_key}"
}

# Extract Event Source
try:
    event_source = alert["rule"]["groups"]
    debug(f"Event source: {event_source}")
except KeyError as e:
    debug(f"Missing expected key in alert: {e}")
    sys.exit(1)

if any(group in ['web', 'sshd', 'invalid_login', 'firewall', 'ids', 'system', 'database', 'application'] for group in event_source):
    try:
        client_ip = alert["data"]["srcip"]  # Extract client IP
        debug(f"Extracted Client IP: {client_ip}")
        if ipaddress.ip_address(client_ip).is_global:
            # Pass the client_ip value directly into the URL
            criminalip_search_url = f'https://api.criminalip.io/v1/asset/ip/report?ip={client_ip}&full=true'
            debug(f"CriminalIP API URL: {criminalip_search_url}")
            try:
                criminalip_api_response = requests.get(criminalip_search_url, headers=criminalip_apicall_headers)
                criminalip_api_response.raise_for_status()  # Raise HTTPError for bad responses
                debug("API request successful")
            except ConnectionError as conn_err:
                alert_output["criminalip"] = {"error": 'Connection Error to CriminalIP API'}
                alert_output["integration"] = "criminalip"
                debug(f"ConnectionError: {conn_err}")
                send_event(alert_output, alert.get("agent"))
            except HTTPError as http_err:
                alert_output["criminalip"] = {"error": f'HTTP Error: {http_err}'}
                alert_output["integration"] = "criminalip"
                debug(f"HTTPError: {http_err}")
                send_event(alert_output, alert.get("agent"))
            except Exception as e:
                alert_output["criminalip"] = {"error": f'Unexpected Error: {e}'}
                alert_output["integration"] = "criminalip"
                debug(f"Unexpected Error: {e}")
                send_event(alert_output, alert.get("agent"))
            else:
                try:
                    criminalip_api_response = criminalip_api_response.json()
                    debug(f"API Response Data: {criminalip_api_response}")
                    # Check if the response contains score information
                    if "score" in criminalip_api_response and criminalip_api_response["score"]:
                        # Generate Alert Output from CriminalIP Response
                        score = criminalip_api_response["score"]
                        issues = criminalip_api_response["issues"]
                        alert_output["criminalip"] = {
                            "ip": criminalip_api_response["ip"],
                            "score_inbound": score.get("inbound", "Unknown"),
                            "score_outbound": score.get("outbound", "Unknown"),
                            "is_vpn": issues.get("is_vpn", False),
                            "is_tor": issues.get("is_tor", False),
                            "is_proxy": issues.get("is_proxy", False),
                            "is_cloud": issues.get("is_cloud", False),
                            "is_hosting": issues.get("is_hosting", False),
                            "is_darkweb": issues.get("is_darkweb", False),
                            "is_scanner": issues.get("is_scanner", False),
                            "is_snort": issues.get("is_snort", False),
                            "is_anonymous_vpn": issues.get("is_anonymous_vpn", False)
                        }
                        alert_output["integration"] = "criminalip"
                        debug(f"Alert Output: {alert_output}")
                        send_event(alert_output, alert.get("agent"))
                    else:
                        alert_output["criminalip"] = {"error": 'No score information found in CriminalIP response'}
                        alert_output["integration"] = "criminalip"
                        debug("No score information found in CriminalIP response")
                        send_event(alert_output, alert.get("agent"))
                except Exception as e:
                    alert_output["criminalip"] = {"error": f"Error parsing JSON response: {e}"}
                    alert_output["integration"] = "criminalip"
                    debug(f"Error parsing JSON response: {e}")
                    send_event(alert_output, alert.get("agent"))
        else:
            debug(f"Client IP is not global: {client_ip}")
            sys.exit()
    except KeyError as e:
        alert_output["criminalip"] = {"error": f'Missing expected key: {e}'}
        alert_output["integration"] = "criminalip"
        debug(f"KeyError: {e}")
        send_event(alert_output, alert.get("agent"))
        sys.exit()
else:
    debug(f"Event source is not found : {event_source}")
    sys.exit()
