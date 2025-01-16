# sysmon_config
 use for misp and wazuh integreated

 .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml


# MISP Scripts
 1. Copy scripts file to /var/ossec/integreation/ path
 2. Edit scripts with your own MISP instance IP and Auth Keys then save
 3. restart wazuh manager [systemctrl restart wazuh-manager]

# MISP Detection Rule [Wazuh]
 1. Go to rule setting 
 2. add copy rule from misp_wazuh_rule.xml and save name to "misp.xml"
 3. restart wazuh manager [systemctrl restart wazuh-manager]

# Active-Response
 Read procedures.