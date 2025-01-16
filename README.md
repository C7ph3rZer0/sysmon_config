# Sysmon Configuration
 This repository provides configuration for integrating Sysmon with MISP and Wazuh.

## Sysmon Setup
 Run the following command to install Sysmon with the provided configuration file:
 .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml

## MISP Scripts
 1. Copy the script files to the `/var/ossec/integration/` path.
 2. Edit the scripts to include your MISP instance's IP address and authentication keys, then save the changes.
 3. Restart the Wazuh manager to apply the changes:
"systemctl restart wazuh-manager"

## MISP Detection Rules (Wazuh)
 1. Navigate to the Wazuh rule settings.
 2. Add the detection rules by copying the content from `misp_wazuh_rule.xml` and saving it as `misp.xml`.
 3. Restart the Wazuh manager to load the new rules:
"systemctl restart wazuh-manager"

## Active-Response
 Follow the provided procedures to configure active responses.
