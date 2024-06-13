import json
import glob
import matplotlib.pyplot as plt
from matplotlib_venn import venn2, venn3, venn3_unweighted  

alert_types = {
    "00b300": {"resolve_time": 60, "severity": "Average"},
    "fc8a08": {"resolve_time": 60, "severity": "Average"},
    "734d00": {"resolve_time": 60, "severity": "Warning"},
    "FF0000": {"resolve_time": 15, "severity": "High"},
}

ignored_hosts = ["host1", "host2"]

total_alerts = 0
self_resolved_alerts = 0
non_critical_alerts = 0
ignored_host_alerts = 0
alert_categories = {
    "Escalated": set(),
    "Self-resolved (on time)": set(),
    "Non-critical": set(),
    "Ignored host": set()
}

open_alerts = {}

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
                    total_alerts += 1
                    if host_name in ignored_hosts:
                        ignored_host_alerts += 1
                        alert_categories["Ignored host"].add(event_id)
                    else:
                        open_alerts[event_id] = {"timestamp": float(message["ts"]), "severity": severity, "host": host_name}
                        if severity in ("00b300", "734d00"):
                            non_critical_alerts += 1
                            alert_categories["Non-critical"].add(event_id)
                        if severity != "FF0000":
                            alert_categories["Escalated"].add(event_id) 

                elif title.startswith("Resolved:") and event_id in open_alerts:
                    alert = open_alerts.pop(event_id)
                    time_diff = float(message["ts"]) - alert["timestamp"]
                    if time_diff <= alert_types.get(alert["severity"], {}).get("resolve_time", 0) * 60:
                        self_resolved_alerts += 1
                        alert_categories["Self-resolved (on time)"].add(event_id)

# Вывод статистики
print("Alert Statistics:")
for category, count in alert_categories.items():
    print(f"  - {category}: {len(count)}")

# Построение диаграммы Венна
venn3_unweighted(
    [alert_categories["Escalated"], alert_categories["Self-resolved (on time)"], alert_categories["Non-critical"]],
    set_labels=("Escalated", "Self-resolved (on time)", "Non-critical"),
)
plt.title("Zabbix Alert Categories")
plt.show()
