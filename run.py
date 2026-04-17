from dojaa.pipeline import run_pipeline

def main():
    data = run_pipeline(use_api=True)

    print("\n--- DOJAA Pipeline Complete ---")
    print(f"Shodan assets: {len(data['shodan'])}")
    print(f"Censys assets: {len(data['censys'])}")

    print("\nSample High Risk Assets:")
    for asset in data["shodan"][:5]:
        print(asset["ip"], asset["risk_score"], asset.get("severity"))

if __name__ == "__main__":
    main()