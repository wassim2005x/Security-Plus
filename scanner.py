import requests



VT_API_KEY = "YOUR_VIRUSTOTAL_KEY"
HA_API_KEY = "YOUR_HYBRIDANALYSIS_KEY"
MS_API_KEY = "YOUR_MALSHARE_KEY"



# ================== VirusTotal ==================
def check_VT(fileHash):

    #virusTotal_Key = "5552916041499bbcd25f41e26c0fd9ec8e3008005b5532973d8faeacf4640193"
    url = "https://www.virustotal.com/api/v3/files/"

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url + fileHash, headers=headers)

    if response.status_code == 200:
        return response.json()
    return None

# ================== MalwareBazaar ==================
def check_MB(fileHash):

    url = "https://mb-api.abuse.ch/api/v1/"
    data = {"query": "get_info" , "hash": fileHash}

    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()
    return None

# ================== ThreatFox ==================
def check_TF(file_hash):

    url = "https://threatfox-api.abuse.ch/api/v1/"
    data = {"query": "search_hash", "hash": file_hash}

    response = requests.post(url, json=data)
    if response.status_code == 200:
        return response.json()
    return None

# ================== Hybrid Analysis ==================
def check_HA(file_hash):

    
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    headers = {
        "api-key": HA_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json"
    }
    data = {"hash": file_hash}

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()
    return None

# ================== MalShare ==================
def check_MalShare(file_hash):

    
    url = f"https://malshare.com/api.php?api_key={MS_API_KEY}&action=details&hash={file_hash}"

    response = requests.get(url)
    if response.status_code == 200:
        try:
            return response.json()  
        except ValueError:
            return {"raw": response.text}  
    return None







