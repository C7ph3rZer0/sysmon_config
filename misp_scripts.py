#!/var/ossec/framework/python/bin/python3
## MISP API Integration (New14 - Enhanced Debugging for IP Matching)

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import requests
import json
import ipaddress
import re

pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = f"{pwd}/queue/sockets/queue"

def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = f"1:misp:{json.dumps(msg)}"
    else:
        string = f"1:[{agent['id']}] ({agent['name']}) {agent.get('ip', 'any')}->misp:{json.dumps(msg)}"
    with socket(AF_UNIX, SOCK_DGRAM) as sock:
        sock.connect(socket_addr)
        sock.send(string.encode())

# Read configuration parameters
alert_file = open(sys.argv[1])
alert = json.loads(alert_file.read())
alert_file.close()

alert_output = {}
misp_base_url = "https://172.16.1.106//attributes/restSearch/"
misp_api_auth_key = "akLngMm8xG07K5X0JPC5L1hwW1ei8wiZ9ngPJuBX"
misp_headers = {
    "Content-Type": "application/json",
    "Authorization": misp_api_auth_key,
    "Accept": "application/json",
}

regex_file_hash = re.compile(r"\b[a-fA-F0-9]{64}\b")

try:
    event_source = alert.get("rule", {}).get("groups", [None, None, None])[0]
    event_type = alert.get("rule", {}).get("groups", [None, None, None])[2]

    if event_source == "windows":
        if event_type in ["sysmon_event1", "sysmon_event6", "sysmon_event7", "sysmon_event_15", "sysmon_event_23", "sysmon_event_24", "sysmon_event_25"]:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"].get("hash", "")).group(0)
        elif event_type == "sysmon_event3":
            print("Processing sysmon_event3...")  # Debugging Log
            try:
                dst_ip = alert["data"]["win"]["eventdata"].get("destinationIp")
                protocol = alert["data"]["win"]["eventdata"].get("protocol")
                print(f"Destination IP: {dst_ip}, Protocol: {protocol}")  # Debugging Log
                if dst_ip and ipaddress.ip_address(dst_ip).is_global and protocol == "tcp":
                    wazuh_event_param = dst_ip
                    print(f"Matched Public TCP IP for MISP: {wazuh_event_param}")  # Debugging Log
                else:
                    print(f"Skipped private IP or non-TCP traffic: {dst_ip}")  # Debugging Log
                    sys.exit()
            except KeyError as e:
                print(f"KeyError: {e}")  # Debugging Log
                sys.exit()
        elif event_type == "sysmon_event_22":
            query_name = alert["data"]["win"]["eventdata"].get("queryName")
            if query_name:
                wazuh_event_param = query_name
            else:
                sys.exit()
        else:
            sys.exit()

        misp_search_url = f"{misp_base_url}value:{wazuh_event_param}"
        response = requests.get(misp_search_url, headers=misp_headers, verify=False)
        misp_data = response.json()

        if "response" in misp_data and misp_data["response"].get("Attribute"):
            attribute = misp_data["response"]["Attribute"][0]
            alert_output = {
                "misp": {
                    "event_id": attribute.get("event_id"),
                    "category": attribute.get("category"),
                    "value": attribute.get("value"),
                    "type": attribute.get("type"),
                    "comment": attribute.get("comment"),
                    "source": {
                        "description": alert["rule"].get("description")
                    }
                },
                "integration": "misp",
            }
            print("Alert Output JSON:", alert_output)  # Debugging Log
            send_event(alert_output, alert.get("agent"))

except Exception as e:
    print(f"Error: {e}")  # Debugging Log
    sys.exit()
