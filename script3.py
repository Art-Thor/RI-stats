# for determining resolution time >5

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
alerts_resolved_within_5_minutes = 0

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
                    open_alerts[event_id] = {"timestamp": float(message["ts"]), "severity": severity, "host": host_name}

                elif title.startswith("Resolved:") and event_id in open_alerts:
                    alert = open_alerts.pop(event_id)
                    time_diff = float(message["ts"]) - alert["timestamp"]
                    if time_diff <= 5 * 60:  # 5 minutes in seconds
                        alerts_resolved_within_5_minutes += 1

# Вывод статистики
print("Total Alerts:", total_alerts)
print("Alerts Resolved Within 5 Minutes:", alerts_resolved_within_5_minutes)
