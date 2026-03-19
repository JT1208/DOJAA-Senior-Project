import json

def save_to_json(data, filename="dashboard_data.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)