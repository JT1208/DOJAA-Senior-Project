import requests

try:
    resp = requests.get("https://api.censys.io")
    print(resp.status_code)
except Exception as e:
    print(e)