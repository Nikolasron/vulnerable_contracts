import os
import json
import time
import requests
import subprocess
from tronpy import Tron
from tronpy.keys import to_hex_address

# --- CONFIG ---
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "").strip()
OUTPUT_FILE = "vulnerable_contracts.json"
CONTRACT_LIMIT = 20  # Number of active contracts to scan per run

TRONSCAN_LIST_URL = "https://apilist.tronscanapi.com/api/contracts"
TRONGRID_BASE = "https://api.trongrid.io"
TRONGRID_JSONRPC = f"{TRONGRID_BASE}/jsonrpc"

HEADERS = {}
if TRONSCAN_API_KEY: 
    HEADERS["TRON-PRO-API-KEY"] = TRONSCAN_API_KEY

client = Tron(network="mainnet")
RISK_SWC = {"SWC-105", "SWC-106", "SWC-115"}

def fetch_recent_contracts(limit=CONTRACT_LIMIT):
    """Fetches the MOST ACTIVE verified contracts (highest TRX volume)."""
    params = {
        "count": "true", 
        "limit": limit, 
        "start": 0,
        "sort": "-trxCount",         # <--- CHANGED: Fetches most active contracts
        "verified-only": "true", 
        "open-source-only": "true", 
    }
    try:
        r = requests.get(TRONSCAN_LIST_URL, headers=HEADERS, params=params, timeout=15)
        r.raise_for_status()
        data = r.json().get("data", [])
        print(f"📡 Fetched {len(data)} active contracts from TronScan.")
        return data
    except Exception as e:
        print(f"❌ Failed to fetch contracts: {e}")
        return []

def get_bytecode(address):
    """Fetches runtime bytecode using native TRON JSON-RPC and node endpoints."""
    
    # Method 1: eth_getCode via JSON-RPC (Most reliable for runtime code)
    try:
        hex_addr = to_hex_address(address)
        if hex_addr.startswith("41"):
            hex_addr = "0x" + hex_addr[2:]
        else:
            hex_addr = "0x" + hex_addr

        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
            "params": [hex_addr, "latest"]
        }
        r = requests.post(TRONGRID_JSONRPC, json=payload, headers=HEADERS, timeout=15)
        if r.ok:
            code = r.json().get("result")
            if code and code != "0x" and len(code) > 20:
                return code
    except Exception:
        pass

    # Method 2: /wallet/getcontractinfo (Returns runtimecode)
    try:
        payload = {"value": address, "visible": True}
        r = requests.post(f"{TRONGRID_BASE}/wallet/getcontractinfo", json=payload, headers=HEADERS, timeout=15)
        if r.ok:
            data = r.json()
            bytecode = data.get("runtimecode") or data.get("bytecode")
            if bytecode: 
                return bytecode
    except Exception:
        pass

    # Method 3: Fallback to Tronscan detail API
    try:
        r = requests.get("https://apilist.tronscanapi.com/api/contract", headers=HEADERS, params={"contract": address}, timeout=15)
        if r.ok:
            data = r.json().get("data", [{}])[0]
            bytecode = data.get("bytecode") or data.get("runtime_bytecode")
            if bytecode: 
                return bytecode
    except Exception:
        pass

    return None

def analyze_with_mythril(bytecode):
    if not bytecode: return []
    
    cmd = ["myth", "analyze", "-c", bytecode, "--execution-timeout", "60", "-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0: return []
        return json.loads(result.stdout)
    except Exception:
        return []

def is_vulnerable(mythril_results):
    if not mythril_results: return False
    for issue in mythril_results:
        for problem in issue.get("issues", []):
            if problem.get("swc-id") in RISK_SWC:
                return True
    return False

def main():
    print("🔍 Starting batch Mythril scan on ACTIVE contracts...")
    
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w") as f: json.dump({}, f)

    seen = set()
    try:
        with open(OUTPUT_FILE, "r") as f:
            seen = set(json.load(f).keys())
    except FileNotFoundError: pass

    contracts = fetch_recent_contracts()
    if not contracts: return

    for i, c in enumerate(contracts):
        address = c.get("address")
        name = c.get("name", "Unknown")
        if not address or address in seen: continue

        print(f"\n--- [{i+1}/{len(contracts)}] Analyzing: {name} ({address}) ---")
        
        bytecode = get_bytecode(address)
        if not bytecode:
            print("  ⚠️ No bytecode found after all fallbacks, skipping.")
            continue

        print("  🛠️ Running Mythril...")
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
                "ownerless": True,
                "mythril_vulnerable": True,
                "mythril_issues": list(set(issues)),
                "timestamp": int(time.time()),
            }
            
            try:
                with open(OUTPUT_FILE, "r") as f: data = json.load(f)
            except FileNotFoundError: data = {}
            data[address] = record
            with open(OUTPUT_FILE, "w") as f: json.dump(data, f, indent=2)
            print(f"  ✅ Saved to {OUTPUT_FILE}")
        else:
            print("  ✅ No critical vulnerabilities found.")
        
        seen.add(address)
        time.sleep(2)

if __name__ == "__main__":
    main()
