import hashlib
import os
import shutil
import requests 
import pyfiglet
import scanner
import time


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
    sigs = set()
    with open(sigfile, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sigs.add(line.split()[0])
    return sigs


def scan(root, sigs):
    for base, folders, files in os.walk(root):
        for nameF in files:
            path = os.path.join(base, nameF)
            try:
                sha = sh(path)
                if sha in sigs:
                    print(f"Local check: VIRUS → {path}")
                    quarantine(path)
                    continue

                #MalwareBazaar
                mb_data = scanner.check_MB(sha)
                if mb_data and mb_data.get("query_status") == "ok":
                    print(f"MalwareBazaar: Match found → {path}")
                    quarantine(path)
                    continue

                #MalShare
                ms_data = scanner.check_MalShare(sha)
                if ms_data and "sha256" in ms_data:
                    print(f"MalShare: Match found → {path}")
                    quarantine(path)
                    continue

                #ThreatFox
                tf_data = scanner.check_TF(sha)
                if tf_data and tf_data.get("query_status") == "ok":
                    print(f"ThreatFox: Match found → {path}")
                    quarantine(path)
                    continue

                #Hybrid Analysis
                ha_data = scanner.check_HA(sha)
                if ha_data and isinstance(ha_data, list) and len(ha_data) > 0:
                    print(f"Hybrid Analysis: Match found → {path}")
                    quarantine(path)
                    continue

                # VirusTotal
                time.sleep(15)
                vt_data = scanner.check_VT(sha)
                if vt_data:
                    positives = vt_data["data"]["attributes"]["last_analysis_stats"]["malicious"]
                    if positives > 0:
                        print(f"VirusTotal: {positives} engines flagged → {path}")
                        quarantine(path)
                        continue

                print(f"Clean → {path}")

            except Exception as e:
                print(f"error {e}")

def quarantine(filePath):
    quar_dir = "/home/mustang/Desktop/antivirus_project/quarantine"
    os.makedirs(quar_dir, exist_ok=True)
    try:
        shutil.move(filePath, quar_dir)
        print(f"{filePath} had quarantined to {quar_dir}")
    except Exception as e:
        print(f"ERROR: Failed to quarantine {filePath} : {e}")

def main():
    #print("welcome to security +")
    ascii_banner = pyfiglet.figlet_format("Security +")
    print(ascii_banner)
    sig = "signatures.txt"
    path = "/home/mustang/Desktop/antivirus_project/testVirus"
    sigs = load_signatures(sig)
    scan(path, sigs)

if __name__ == "__main__":
    main()
