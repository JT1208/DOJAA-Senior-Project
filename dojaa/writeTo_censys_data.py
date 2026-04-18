import json

def save_results(results, filename="censys_data.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"Results written to {filename}")