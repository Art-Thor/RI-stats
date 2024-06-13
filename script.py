import json
import glob

alert_types = {
    "00b300": {"resolve_time": 60},  
    "fc8a08": {"resolve_time": 60},  
    "734d00": {"resolve_time": 60},  
    "FF0000": {"resolve_time": 15},
}

ignored_hosts = ["host1", "host2"]

# Move open_alerts declaration outside the loop
open_alerts = {}
total_alerts = 0
self_resolved_alerts = 0
non_critical_alerts = 0
ignored_host_alerts = 0
hosts_in_progress = {} 

for filename in glob.glob('*.json'):
    with open(filename, 'r') as f:
        data = json.load(f)

        for message in data:
            if "username" in message and message["username"] == "zabbix":
                title = message["attachments"][0]["title"].replace(" ", "")
                severity = message["attachments"][0]["color"]
                host_name = message["attachments"][0]["text"].split("\n")[0].split(": ")[1]
                event_url = message["attachments"][0]["text"].split("\n")[-1]
                event_id = event_url.split("eventid=")[1].split(">")[0] if "eventid=" in event_url else None

                if title.startswith("Problem:"):
                    if host_name in ignored_hosts:
                        ignored_host_alerts += 1
                    else:
                        total_alerts += 1
                        open_alerts[event_id] = {"timestamp": float(message["ts"]), "severity": severity, "host": host_name}
                        if severity in ("00b300", "734d00"):
                            non_critical_alerts += 1

                        if any(keyword in host_name for keyword in ["mcestag", "puxira", "eto"]):
                            hosts_in_progress[host_name] = hosts_in_progress.get(host_name, 0) + 1

                elif title.startswith("Resolved:") and event_id in open_alerts:
                    alert = open_alerts.pop(event_id)
                    time_diff = float(message["ts"]) - alert["timestamp"]
                    if time_diff <= alert_types.get(alert["severity"], {}).get("resolve_time", 0) * 60:
                        self_resolved_alerts += 1

                    # Уменьшаем счетчик алертов для хоста, если алерт решен
                    if alert["host"] in hosts_in_progress:
                        hosts_in_progress[alert["host"]] -= 1
                        if hosts_in_progress[alert["host"]] == 0:
                            del hosts_in_progress[alert["host"]]  # Удаляем хост, если нет открытых алертов

# Подсчет алертов в работе
alerts_in_progress_count = len(open_alerts)

print(f"Total alerts: {total_alerts}")
print(f"Self-resolved alerts (on time): {self_resolved_alerts}")
print(f"Non-critical alerts: {non_critical_alerts}")
print(f"Alerts from ignored hosts: {ignored_host_alerts}")
print(f"Alerts in progress: {alerts_in_progress_count}")
print(f"Alerts in progress by host:")
for host, count in hosts_in_progress.items():
    print(f"  - {host}: {count}")
