import hashlib
import os
import shutil
import pyfiglet
import scanner
import time
import threading
import psutil
from concurrent.futures import ThreadPoolExecutor
import logging
import json
from datetime import datetime

# Configure logging
logging.basicConfig(
    filename='antivirus.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

pending_vt = []   
lock = threading.Lock()


def sh(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def load_signatures(sigfile):
    """Load malware signatures from file"""
    sigs = set()
    
    # Check if file exists, create empty one if not
    if not os.path.exists(sigfile):
        print(f"⚠️  Signature file not found: {sigfile}")
        print(f"📝 Creating empty signature file...")
        try:
            with open(sigfile, "w") as f:
                f.write("# Add SHA256 malware hashes here (one per line)\n")
                f.write("# Example:\n")
                f.write("# 2b61f98a04f969abf7b900553c6d977103f4efe9539044d9a6f994c07cb477e2\n")
            print(f"✅ Created: {sigfile}")
        except Exception as e:
            print(f"❌ Could not create signature file: {e}")
            logging.error(f"Failed to create signature file: {e}")
        return sigs
    
    # Load signatures
    try:
        with open(sigfile, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                sigs.add(line.split()[0])
        
        print(f"✅ Loaded {len(sigs)} signatures from {sigfile}")
        logging.info(f"Loaded {len(sigs)} signatures")
        return sigs
        
    except Exception as e:
        print(f"❌ Error loading signatures: {e}")
        logging.error(f"Failed to load signatures: {e}")
        return sigs


def scan_file(path, sigs):
    try:
        sha = sh(path)
        if sha in sigs:
            print(f"Local check: VIRUS → {path}")
            quarantine(path)
            return

        # MalwareBazaar
        mb_data = scanner.check_MB(sha)
        if mb_data and mb_data.get("query_status") == "ok":
            print(f"MalwareBazaar: Match found → {path}")
            quarantine(path)
            return

        # MalShare
        ms_data = scanner.check_MalShare(sha)
        if ms_data and "sha256" in ms_data:
            print(f"MalShare: Match found → {path}")
            quarantine(path)
            return

        # ThreatFox
        tf_data = scanner.check_TF(sha)
        if tf_data and tf_data.get("query_status") == "ok":
            print(f"ThreatFox: Match found → {path}")
            quarantine(path)
            return

        # Hybrid Analysis
        ha_data = scanner.check_HA(sha)
        if ha_data and isinstance(ha_data, list) and len(ha_data) > 0:
            print(f"Hybrid Analysis: Match found → {path}")
            quarantine(path)
            return

        # Queue for VirusTotal
        with lock:
            pending_vt.append((sha, path))

    except PermissionError:
        logging.warning(f"Permission denied: {path}")
    except FileNotFoundError:
        logging.warning(f"File not found: {path}")
    except Exception as e:
        logging.error(f"Unexpected error scanning {path}: {e}")


def full_scan(sigs):
    print("\n" + "="*60)
    print("🛡️  FULL SYSTEM SCAN INITIATED")
    print("="*60)
    
    for partition in psutil.disk_partitions():
        print(f"\n📀 Scanning drive: {partition.mountpoint}")
        print(f"   Device: {partition.device}")
        print(f"   Type: {partition.fstype}")
        
        try:
            scan(partition.mountpoint, sigs)
        except PermissionError:
            msg = f"Permission denied for {partition.device}"
            print(f"⚠️  {msg}")
            logging.warning(msg)
        except Exception as e:
            msg = f"Error scanning {partition.device}: {e}"
            print(f"❌ {msg}")
            logging.error(msg)
    
    print("\n" + "="*60)
    print("✅ FULL SCAN COMPLETE")
    print("="*60)
                      




def scan(root, sigs):
    print(f"\n🔍 Scanning: {root}")
    
    # Collect all files first
    files_to_scan = []
    for base, folders, files in os.walk(root):
        for nameF in files:
            path = os.path.join(base, nameF)
            files_to_scan.append(path)
    
    total_files = len(files_to_scan)
    print(f"📁 Found {total_files} files to scan\n")
    
    if total_files == 0:
        return
    
    scanned = 0
    
    # Use ThreadPoolExecutor with max 10 workers (prevents explosion)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for path in files_to_scan:
            future = executor.submit(scan_file, path, sigs)
            futures.append(future)
        
        # Wait for all scans to complete
        for future in futures:
            try:
                future.result()
                scanned += 1
                if scanned % 100 == 0:
                    print(f"⏳ Progress: {scanned}/{total_files} files scanned")
            except Exception as e:
                print(f"Scan error: {e}")
    
    
    # Copy and clear pending_vt safely
    with lock:
        vt_queue = list(pending_vt)
        pending_vt.clear()

    print(f"\n=== Starting VirusTotal checks ({len(vt_queue)} files) ===")

    for sha, path in vt_queue:
        print(f"Waiting 20s before VT check for {path}...")
        for i in range(20, 0, -1):
            time.sleep(1)
            print(f"{i} s ...")  
    
        vt_data = scanner.check_VT(sha)
        if vt_data:
            positives = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            if positives > 0:
                print(f"VirusTotal: {positives} engines flagged → {path}")
                quarantine(path)
                continue
        print(f"Clean (after VT) → {path}")

            


def quarantine(filePath):
    quar_dir = os.path.join(os.getcwd(), "quarantine")
    os.makedirs(quar_dir, exist_ok=True)
    
    # Create unique filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(filePath)
    safe_name = f"{timestamp}_{base_name}.quarantined"
    dest = os.path.join(quar_dir, safe_name)
    
    # Compute hash before moving
    try:
        file_hash = sh(filePath)
    except:
        file_hash = "unknown"
    
    # Create metadata file
    metadata = {
        "original_path": filePath,
        "quarantine_time": timestamp,
        "sha256": file_hash,
        "original_name": base_name
    }
    
    try:
        # Save metadata
        with open(dest + ".json", "w") as f:
            json.dump(metadata, f, indent=2)
        
        # Move file
        shutil.move(filePath, dest)
        
        # Remove all permissions (security)
        os.chmod(dest, 0o000)
        
        print(f"🛡️  QUARANTINED: {filePath} → {dest}")
        logging.info(f"Quarantined: {filePath}")
        
    except Exception as e:
        logging.error(f"Failed to quarantine {filePath}: {e}")
        print(f"❌ Quarantine failed: {e}")

def main():
    ascii_banner = pyfiglet.figlet_format("Security +")
    print(ascii_banner)
    sig = "signatures.txt"
    sigs = load_signatures(sig)
    time.sleep(2)

    while True:
        print("\n" + "="*50)
        print("Enter your choice:")
        print("1- Full computer scan")
        print("2- Enter the folder path to scan")
        print("3- Exit")
        print("="*50)
        choice = input("\nChoice: ").strip()

        if choice == "1":
            confirm = input("⚠️  Full scan may take hours. Continue? (yes/no): ").strip().lower()
            if confirm == "yes":
                full_scan(sigs)
            break
            
        elif choice == "2":
            print("Enter the folder path here:")
            path = input().strip()
            if os.path.isdir(path):
                scan(path, sigs)
            else:
                print(f"❌ Invalid path: {path}")
                continue
            break
            
        elif choice == "3":
            print("Exiting...")
            break
            
        else:
            print("❌ Invalid choice. Try again.")
    
                       
              

    

if __name__ == "__main__":
    main()
