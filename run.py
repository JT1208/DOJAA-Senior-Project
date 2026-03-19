# run.py
from dojaa.pipeline import run_pipeline

def main():
    data = run_pipeline(use_api=True)
    print("Pipeline finished successfully.")
    print("Sample Shodan entries:", data["shodan"][:5])
    print("Sample Censys entries:", data["censys"][:5])

if __name__ == "__main__":
    main()