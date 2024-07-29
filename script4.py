# for determining resolution time for different timings

import json
import glob

alert_types = {
    "00b300": {"resolve_time": 60, "severity": "Average"},
    "fc8a08": {"resolve_time": 60, "severity": "Average"},
    "734d00": {"resolve_time": 60, "severity": "Warning"},
    "FF0000": {"resolve_time": 15, "severity": "High"},
}

total_alerts = 0
alert_counts = {
    "<= 5 min": 0,
    "<= 6 min": 0,
    "<= 7 min": 0,
    "<= 8 min": 0,
    "<= 9 min": 0,
    "<= 10 min": 0,
    "> 10 min": 0
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
                    open_alerts[event_id] = {"timestamp": float(message["ts"]), "severity": severity, "host": host_name}

                elif title.startswith("Resolved:") and event_id in open_alerts:
                    alert = open_alerts.pop(event_id)
                    time_diff = float(message["ts"]) - alert["timestamp"]
                    
                    if time_diff <= 5 * 60:
                        alert_counts["<= 5 min"] += 1
                    elif time_diff <= 6 * 60:
                        alert_counts["<= 6 min"] += 1
                    elif time_diff <= 7 * 60:
                        alert_counts["<= 7 min"] += 1
                    elif time_diff <= 8 * 60:
                        alert_counts["<= 8 min"] += 1
                    elif time_diff <= 9 * 60:
                        alert_counts["<= 9 min"] += 1
                    elif time_diff <= 10 * 60:
                        alert_counts["<= 10 min"] += 1
                    else:
                        alert_counts["> 10 min"] += 1

# Вывод статистики
print("Total Alerts:", total_alerts)
print("Alert Resolution Time Statistics:")
for category, count in alert_counts.items():
    print(f"  - {category}: {count}")
