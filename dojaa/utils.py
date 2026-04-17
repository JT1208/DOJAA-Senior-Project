def print_asset(asset):
    """
    Pretty prints a DOJAA asset record.
    """

    print(
        f"{asset.get('ip')} "
        f"({asset.get('service', 'Unknown')}:{asset.get('port')}) "
        f"- Risk: {asset.get('risk_score', 0)} "
        f"- Severity: {asset.get('severity', 'N/A')}"
    )