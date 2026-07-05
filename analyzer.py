import argparse
import base64
import colorama
import hashlib
import json
import os
import re
import time
from email import message_from_bytes
from email.policy import default
import requests
from dotenv import load_dotenv
from tabulate import tabulate

# Initialize colorama for colored terminal output (autoreset ensures colors don't leak)
colorama.init(autoreset=True)

# Load environment variables from the .env file
load_dotenv()

def parse_email_file(file_path):
    """
    Reads a raw .eml file and returns an email Message object.
    
    Args:
        file_path (str): Path to the .eml file.
        
    Returns:
        email.message.Message: The parsed email message object.
    """
    try:
        # Open the file in binary read mode ('rb') to handle different encodings and raw attachment bytes.
        with open(file_path, 'rb') as f:
            # Use default policy to automatically handle standard header parsing and decoding.
            return message_from_bytes(f.read(), policy=default)
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{file_path}' was not found.")
    except PermissionError:
        raise PermissionError(f"Permission denied accessing '{file_path}'.")
    except Exception as e:
        raise ValueError(f"Failed to parse email file. It may be corrupt or malformed. Details: {e}")

def is_public_ip(ip_str):
    """
    Checks if an IP address is a public IPv4 address (not private, loopback, or link-local).
    This helps filter out internal host IPs and isolate the external sender IP.
    
    Args:
        ip_str (str): The IP address to check.
        
    Returns:
        bool: True if it is a public IP, False otherwise.
    """
    try:
        parts = [int(p) for p in ip_str.split('.')]
        if len(parts) != 4:
            return False
            
        # Private IPv4 ranges:
        # 10.0.0.0/8
        if parts[0] == 10:
            return False
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return False
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return False
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return False
        # 169.254.0.0/16 (link-local autoconfiguration)
        if parts[0] == 169 and parts[1] == 254:
            return False
            
        return True
    except ValueError:
        return False

def check_ip_abuse(ip_address):
    """
    Queries the AbuseIPDB API v2 to check the abuse confidence score of an IP address.
    
    Args:
        ip_address (str): The IP address to check.
        
    Returns:
        dict: The response data dictionary from AbuseIPDB, or a dict containing an 'error' message.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key or api_key == "YOUR_ABUSEIPDB_API_KEY_HERE":
        return {"error": "AbuseIPDB API key is missing or not configured in .env"}
        
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {})
        else:
            # Parse error message from AbuseIPDB API if possible
            try:
                error_msg = response.json().get("errors", [{}])[0].get("detail", f"Status code {response.status_code}")
            except Exception:
                error_msg = f"Status code {response.status_code}"
            return {"error": error_msg}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}

# Track the timestamp of the last VirusTotal request to manage free-tier rate limits (4 requests/minute)
last_vt_request_time = 0.0

def rate_limit_vt():
    """
    Enforces a delay of 15 seconds between successive requests to VirusTotal
    to respect the free tier rate limit of 4 requests per minute.
    """
    global last_vt_request_time
    current_time = time.time()
    elapsed = current_time - last_vt_request_time
    if elapsed < 15.0:
        sleep_time = 15.0 - elapsed
        print(f"[*] Rate limiting: Sleeping for {sleep_time:.2f} seconds before querying VirusTotal...")
        time.sleep(sleep_time)
    last_vt_request_time = time.time()

def check_vt_hash(file_hash):
    """
    Queries the VirusTotal API v3 for a file hash (MD5 or SHA-256).
    
    Args:
        file_hash (str): The hash of the attachment file.
        
    Returns:
        dict: Analysis statistics or error information.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "VirusTotal API key is missing or not configured in .env"}
        
    rate_limit_vt()
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            return {"status": "Not Found", "message": "Hash not found in VirusTotal database"}
        else:
            return {"error": f"VirusTotal API error: Status code {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}

def check_vt_url(target_url):
    """
    Queries the VirusTotal API v3 for a URL.
    
    To check a URL in VirusTotal API v3:
    1. The URL must be encoded in URL-safe Base64.
    2. The padding ('=') at the end of the base64 string must be stripped.
    
    Args:
        target_url (str): The URL to check.
        
    Returns:
        dict: Analysis statistics or error information.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or api_key == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "VirusTotal API key is missing or not configured in .env"}
        
    rate_limit_vt()
    
    # Base64 encode the URL, make it URL-safe, and remove padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        elif response.status_code == 404:
            return {"status": "Not Found", "message": "URL not found in VirusTotal database"}
        else:
            return {"error": f"VirusTotal API error: Status code {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}"}

def extract_originating_ip(msg):
    """
    Extracts the originating sender IP address from the oldest 'Received' header.
    
    In SMTP transmission, each mail server (MTA) appends a 'Received' header at the top
    of the email when it receives it. Therefore:
    - The top-most 'Received' header is the final hop (newest).
    - The bottom-most 'Received' header is the first hop (oldest), which typically
      contains the IP address of the sender's client or original mail server.
      
    Args:
        msg (email.message.Message): The parsed email message object.
        
    Returns:
        str: The extracted public IP address, or None if not found.
    """
    # Retrieve all 'Received' headers. Returns a list of header values as strings.
    received_headers = msg.get_all('Received', [])
    if not received_headers:
        return None
        
    # We iterate backwards through the headers list (from bottom/oldest to top/newest)
    for header in reversed(received_headers):
        # Regular expression to find IPv4 address format (e.g. 192.0.2.1)
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', header)
        for ip in ips:
            # We want to identify the first external public IP in the chain
            if is_public_ip(ip):
                return ip
    return None

def extract_urls(msg):
    """
    Extracts all unique HTTP/HTTPS URLs from the email body (plain text and HTML).
    
    Args:
        msg (email.message.Message): The parsed email message object.
        
    Returns:
        list: A list of unique URLs found in the email.
    """
    urls = set()
    # Regular expression matching http:// and https:// URLs, including query parameters
    url_regex = re.compile(r'https?://[a-zA-Z0-9\-\._~:/\?#\[\]@!\$&\'\(\)\*\+,;=%]+')
    
    # msg.walk() recursively iterates through every MIME part of the email
    # (e.g. text/plain, text/html, attachments)
    for part in msg.walk():
        # We only want to look for URLs in the text-based parts of the email
        if part.get_content_maintype() == 'text':
            try:
                # get_payload(decode=True) returns the raw bytes decoded from transfer encoding (like Base64/Quoted-Printable)
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                # Determine charset (default to utf-8 if not defined) and decode to string
                charset = part.get_content_charset() or 'utf-8'
                text = payload.decode(charset, errors='ignore')
                
                # Find all matching URLs in this part's content
                found_urls = url_regex.findall(text)
                for url in found_urls:
                    # Strip common trailing punctuation marks that might be caught at the end of a URL in sentences
                    cleaned_url = url.rstrip('.,);:>?!"\'')
                    urls.add(cleaned_url)
            except Exception:
                # Ignore errors decoding specific sections; continue checking the rest
                pass
                
    return list(urls)

def extract_attachments(msg):
    """
    Extracts the names, sizes, and MD5/SHA-256 hashes of attachments within the email.
    
    Args:
        msg (email.message.Message): The parsed email message object.
        
    Returns:
        list: A list of dictionaries containing filename, size in bytes, md5, and sha256.
    """
    attachments = []
    
    # Iterate through MIME parts to locate files
    for part in msg.walk():
        # Check the 'Content-Disposition' header for 'attachment'
        content_disposition = part.get_content_disposition()
        filename = part.get_filename()
        
        # If Content-Disposition says attachment, or if it has an explicit filename
        if content_disposition == 'attachment' or filename:
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            
            # Calculate hashes only if payload is not empty
            md5_hash = "N/A"
            sha256_hash = "N/A"
            if payload:
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
            
            # get_filename() automatically decodes header-encoded names (e.g., RFC 2231/RFC 2047)
            attachments.append({
                'filename': filename or 'Unnamed_Attachment',
                'size': size,
                'md5': md5_hash,
                'sha256': sha256_hash
            })
            
    return attachments

def get_vt_reputation_str(vt_res):
    """
    Helper to get colorized reputation string and stats from VirusTotal analysis results.
    
    Args:
        vt_res (dict): VirusTotal API response dict.
        
    Returns:
        tuple: (reputation_string, statistics_string)
    """
    R = colorama.Fore.RED + colorama.Style.BRIGHT
    Y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    G = colorama.Fore.GREEN + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    
    if "error" in vt_res:
        return f"{Y}Skipped (No API Key){RESET}", "N/A"
    elif "status" in vt_res and vt_res["status"] == "Not Found":
        return f"{G}Clean (Not Found in VT){RESET}", "0 / 0 / 0 / 0"
    
    mal = vt_res.get("malicious", 0)
    sus = vt_res.get("suspicious", 0)
    har = vt_res.get("harmless", 0)
    und = vt_res.get("undetected", 0)
    
    stats_str = f"M:{mal} S:{sus} H:{har} U:{und}"
    
    if mal > 0:
        rep = f"{R}MALICIOUS ({mal} detections){RESET}"
    elif sus > 0:
        rep = f"{Y}SUSPICIOUS ({sus} detections){RESET}"
    else:
        rep = f"{G}CLEAN{RESET}"
        
    return rep, stats_str

def get_ip_reputation_str(ip_res):
    """
    Helper to get colorized reputation string from AbuseIPDB check results.
    
    Args:
        ip_res (dict): AbuseIPDB API response dict.
        
    Returns:
        str: Colorized reputation description.
    """
    R = colorama.Fore.RED + colorama.Style.BRIGHT
    Y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    G = colorama.Fore.GREEN + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    
    if "error" in ip_res:
        return f"{Y}Skipped (No API Key){RESET}"
        
    score = ip_res.get("abuseConfidenceScore", 0)
    if score >= 50:
        return f"{R}HIGH RISK ({score}% Abuse Score){RESET}"
    elif score > 0:
        return f"{Y}SUSPICIOUS ({score}% Abuse Score){RESET}"
    else:
        return f"{G}CLEAN (0% Abuse Score){RESET}"

def main():
    # Setup argparse to accept EML file and optional JSON output path
    parser = argparse.ArgumentParser(description="Phishing IOC Extraction Tool - CLI Analyzer")
    parser.add_argument("eml_path", help="Path to the raw .eml file to analyze")
    parser.add_argument("-o", "--output", help="Path to save the generated report in JSON format")
    args = parser.parse_args()
    
    # Define color shortcuts
    R = colorama.Fore.RED + colorama.Style.BRIGHT
    Y = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    G = colorama.Fore.GREEN + colorama.Style.BRIGHT
    C = colorama.Fore.CYAN + colorama.Style.BRIGHT
    W = colorama.Fore.WHITE + colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    
    # Basic check to see if the file exists
    if not os.path.exists(args.eml_path):
        print(f"{R}Error: File '{args.eml_path}' does not exist.{RESET}")
        return
        
    print(f"{C}[*] Analyzing email file: {args.eml_path}{RESET}\n")
    
    # Parse the email EML file with proper exception handling
    try:
        msg = parse_email_file(args.eml_path)
    except Exception as e:
        print(f"{R}Error: {e}{RESET}")
        return
    
    # Extract email metadata headers
    subject = msg.get('Subject', '(No Subject)')
    sender = msg.get('From', '(No Sender)')
    recipient = msg.get('To', '(No Recipient)')
    
    # Perform IOC extraction
    originating_ip = extract_originating_ip(msg)
    urls = extract_urls(msg)
    attachments = extract_attachments(msg)
    
    # Initialize dictionary for accumulating JSON output data
    report_data = {
        "email_file": args.eml_path,
        "headers": {
            "subject": subject,
            "from": sender,
            "to": recipient
        },
        "originating_ip": {
            "ip": originating_ip,
            "reputation": {}
        },
        "urls": [],
        "attachments": []
    }
    
    # 1. Email Headers Output
    headers_data = [
        ["Subject", subject],
        ["From", sender],
        ["To", recipient]
    ]
    print(C + "==========================================================")
    print(C + "                  EMAIL HEADER DETAILS                    ")
    print(C + "==========================================================")
    print(tabulate(headers_data, headers=["Header Field", "Value"], tablefmt="grid"))
    print()
    
    # 2. Originating IP Reputation Output
    print(C + "==========================================================")
    print(C + "                  SENDER IP REPUTATION                    ")
    print(C + "==========================================================")
    print(f"Originating IP: {W}{originating_ip or 'None Found'}{RESET}")
    if originating_ip:
        ip_res = check_ip_abuse(originating_ip)
        report_data["originating_ip"]["reputation"] = ip_res
        rep_str = get_ip_reputation_str(ip_res)
        print(f"Reputation:     {rep_str}")
        if "error" not in ip_res:
            print(f"Country:        {ip_res.get('countryCode', 'N/A')}")
            print(f"Usage Type:     {ip_res.get('usageType', 'N/A')}")
            print(f"ISP:            {ip_res.get('isp', 'N/A')}")
            print(f"Total Reports:  {ip_res.get('totalReports', 0)}")
    print()
    
    # 3. URL Analysis Output
    print(C + "==========================================================")
    print(C + "                      URL ANALYSIS                        ")
    print(C + "==========================================================")
    if not urls:
        print("No URLs extracted from email body.")
    else:
        urls_table_data = []
        for url in urls:
            print(f"[*] Querying VirusTotal for URL: {url}...")
            vt_res = check_vt_url(url)
            report_data["urls"].append({
                "url": url,
                "vt_results": vt_res
            })
            rep_str, stats_str = get_vt_reputation_str(vt_res)
            urls_table_data.append([url, stats_str, rep_str])
            
        print()
        print(tabulate(urls_table_data, headers=["URL", "VT Stats (M/S/H/U)", "Reputation"], tablefmt="grid"))
    print()
    
    # 4. Attachment Analysis Output
    print(C + "==========================================================")
    print(C + "                   ATTACHMENT ANALYSIS                    ")
    print(C + "==========================================================")
    if not attachments:
        print("No attachments found in email.")
    else:
        attach_table_data = []
        for attachment in attachments:
            name = attachment['filename']
            size = f"{attachment['size']} bytes"
            sha256 = attachment['sha256']
            
            vt_res = {}
            if sha256 != "N/A":
                print(f"[*] Querying VirusTotal for File Hash: {sha256}...")
                vt_res = check_vt_hash(sha256)
                rep_str, stats_str = get_vt_reputation_str(vt_res)
            else:
                rep_str = f"{RESET}N/A"
                stats_str = "N/A"
                
            report_data["attachments"].append({
                "filename": name,
                "size_bytes": attachment['size'],
                "md5": attachment['md5'],
                "sha256": sha256,
                "vt_results": vt_res
            })
            
            # Abbreviate SHA-256 in tables to keep output wide-screen clean
            short_sha = sha256[:12] + "..." if sha256 != "N/A" else "N/A"
            attach_table_data.append([name, size, short_sha, stats_str, rep_str])
            
        print()
        print(tabulate(attach_table_data, headers=["Filename", "Size", "SHA-256 (Trunc)", "VT Stats (M/S/H/U)", "Reputation"], tablefmt="grid"))
    print()

    # Save to JSON file if option is provided
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4)
            print(f"{G}[+] Report successfully saved to: {args.output}{RESET}\n")
        except Exception as e:
            print(f"{R}[-] Failed to save report to JSON: {e}{RESET}\n")
        
if __name__ == "__main__":
    main()
