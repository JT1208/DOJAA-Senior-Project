def print_asset(asset):
    print(f"{asset['ip']} ({asset.get('service', 'Unknown')}:{asset.get('port')}) - Risk {asset.get('risk_score', 0)}")a