#wazuh
.V8lx.e*wLzfDCSsp?+L.x7DT4+n3xMK
#virustotal 
```121719db073e9ba65aeeb107d4910f4b997b78dfab5e785814e56c47ededae87```
#command
```
sudo systemctl restart wazuh-manager
sudo nano /var/ossec/etc/decoders/local_decoder.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo nano /var/ossec/etc/rules/local_rules.xml
sudo nano /var/ossec/etc/ossec.conf
sudo tail -f /var/ossec/logs/alerts/alerts.log
sudo tail -f /var/ossec/logs/archives/archives.log

sudo tcpdump -i any udp port 514 -A -nn
sudo ls /var/ossec/ruleset/rules/

sudo ss -tulpn | grep 514
```


```
sudo tail -f /var/log/apache2/access.log
sudo systemctl status apache2
sudo cp ~/dacn/shop.php /var/www/html/shop.php
sudo cp dacn/shop.php /var/www/html/shop.php
http://localhost/shop.php
http://192.168.20.129/shop.php
sudo tail -n 20 /var/ossec/logs/ossec.log
```

```
ssh admin@192.168.20.128
ssh kali@192.168.20.129
```

```
 grep -A 20 "app-layer:" /usr/local/etc/suricata/suricata.yaml
```
cert win
```
Nhấn phím `Windows + R`, gõ **`certmgr.msc`** (cho người dùng hiện tại) hoặc **`certlm.msc`** (cho toàn bộ máy tính) và nhấn Enter.
```

```
sudo nft list ruleset

```

```
sudo ip route del default
sudo ip route add default via 192.168.10.133 dev eth0

```

```
sudo ip route del default
sudo ip route add default via 192.168.20.128
```


MITRE ATTCK
```
docker run -d \
  --name mitre-neo4j \
  -p 7474:7474 \
  -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/mitre2024 \
  -e NEO4J_PLUGINS='["apoc"]' \
  -e NEO4J_dbms_security_procedures_unrestricted=apoc.* \
  neo4j:5.15-community


```
