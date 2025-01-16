# sysmon_config
 use for misp and wazuh integreated

 .\Sysmon64.exe -accepteula -i sysmonconfig-export.xml


# MISP Scripts
 1. Copy scripts file to /var/ossec/integreation/ path
 2. Edit scripts with your own MISP instance IP and Auth Keys then save
 3. restart wazuh manager [systemctrl restart wazuh-manager]