# run.py
from dojaa.pipeline import run_pipeline

if __name__ == "__main__":
    results = run_pipeline()
    for r in results:
        print(r)