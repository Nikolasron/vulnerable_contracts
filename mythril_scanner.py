import os
import json
import time
import requests
import subprocess
from tronpy import Tron

# --- CONFIG ---
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY", "")
OUTPUT_FILE = "vulnerable_contracts.json"
CONTRACT_LIMIT = 20  # Number of recent contracts to scan per run

TRONSCAN_LIST_URL = "https://apilist.tronscanapi.com/api/contracts"
TRONSCAN_DETAIL_URL = "https://apilist.tronscanapi.com/api/contract"
TRONGRID_BASE = "https://api.trongrid.io"
HEADERS = {}
if TRONSCAN_API_KEY: HEADERS["TRON-PRO-API-KEY"] = TRONSCAN_API_KEY
if TRONGRID_API_KEY: HEADERS["TRON-PRO-API-KEY"] = TRONGRID_API_KEY

client = Tron(network="mainnet")

# SWC IDs that indicate access control failures
RISK_SWC = {"SWC-105", "SWC-106", "SWC-115"}

def fetch_recent_contracts(limit=CONTRACT_LIMIT):
    """Fetches recent verified contracts from TronScan."""
    params = {
        "count": "true", "limit": limit, "start": 0,
        "sort": "-timestamp", "verified-only": "true", "open-source-only": "false",
    }
    try:
        r = requests.get(TRONSCAN_LIST_URL, headers=HEADERS, params=params, timeout=15)
        r.raise_for_status()
        data = r.json().get("data", [])
        print(f"📡 Fetched {len(data)} contracts from TronScan.")
        return data
    except Exception as e:
        print(f"❌ Failed to fetch contracts: {e}")
        return []

def get_bytecode(address):
    """Fetches bytecode from TronGrid, falling back to TronScan."""
    # Try TronGrid
    url = f"{TRONGRID_BASE}/wallet/getcontract"
    try:
        r = requests.post(url, json={"value": address, "visible": True}, headers=HEADERS, timeout=15)
        if r.ok:
            bytecode = r.json().get("bytecode")
            if bytecode: return bytecode
    except Exception: pass

    # Fallback to TronScan
    try:
        r = requests.get(TRONSCAN_DETAIL_URL, headers=HEADERS, params={"contract": address}, timeout=15)
        if r.ok:
            data = r.json().get("data", [{}])[0]
            return data.get("bytecode")
    except Exception: pass
    return None

def analyze_with_mythril(bytecode):
    """Runs Mythril on bytecode and returns JSON findings."""
    if not bytecode: return []
    
    cmd = [
        "myth", "analyze", "-c", bytecode,
        "--execution-timeout", "60", "-o", "json"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"  ⚠️ Mythril error: {result.stderr}")
            return []
        return json.loads(result.stdout)
    except Exception as e:
        print(f"  ⚠️ Analysis failed: {e}")
        return []

def is_vulnerable(mythril_results):
    """Returns True if Mythril found a relevant SWC."""
    if not mythril_results: return False
    for issue in mythril_results:
        for problem in issue.get("issues", []):
            if problem.get("swc-id") in RISK_SWC:
                return True
    return False

def main():
    print("🔍 Starting batch Mythril scan...")
    
    # Ensure output file exists
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w") as f: json.dump({}, f)

    seen = set()
    try:
        with open(OUTPUT_FILE, "r") as f:
            seen = set(json.load(f).keys())
    except FileNotFoundError: pass

    contracts = fetch_recent_contracts()

    for i, c in enumerate(contracts):
        address = c.get("address")
        name = c.get("name", "Unknown")
        if not address or address in seen: continue

        print(f"\n--- [{i+1}/{len(contracts)}] Analyzing: {name} ({address}) ---")
        
        bytecode = get_bytecode(address)
        if not bytecode:
            print("  ⚠️ No bytecode, skipping.")
            continue

        results = analyze_with_mythril(bytecode)
        
        if is_vulnerable(results):
            print("  🚨 HIGH RISK: Access control issue detected!")
            issues = []
            for issue in results:
                for problem in issue.get("issues", []):
                    if problem.get("swc-id") in RISK_SWC:
                        issues.append(problem.get("title"))
            
            record = {
                "address": address, "name": name,
                "ownerless": True,  # Flagged as ownerless due to SWC
                "mythril_vulnerable": True,
                "mythril_issues": list(set(issues)),
                "timestamp": int(time.time()),
            }
            
            # Save result
            try:
                with open(OUTPUT_FILE, "r") as f: data = json.load(f)
            except FileNotFoundError: data = {}
            data[address] = record
            with open(OUTPUT_FILE, "w") as f: json.dump(data, f, indent=2)
            print(f"  ✅ Saved to {OUTPUT_FILE}")
        
        seen.add(address)
        time.sleep(2)  # Rate limit protection

if __name__ == "__main__":
    main()
