from colorama import Style, Fore
from rich.console import Console
from rich.panel import Panel
import pyfiglet
import requests
import os
import time
import hashlib
import mimetypes


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_KEY")


def print_analysis_report(stats) -> None:
    for stat in stats.keys():
        num = str(stats[stat])
        if stat == "malicious":
            print(Fore.RED + Style.BRIGHT + stat + ": " + Style.RESET_ALL + num)
        elif stat == "suspicious":
            print(Fore.YELLOW + Style.BRIGHT + stat + ": " + Style.RESET_ALL + num)
        elif stat == "undetected":
            print(Fore.WHITE + Style.BRIGHT + stat + ": " + Style.RESET_ALL + num)
        elif stat == "harmless":
            print(Fore.GREEN + Style.BRIGHT + stat + ": " + Style.RESET_ALL + num)
        elif stat == "timeout":
            print(Fore.MAGENTA + Style.BRIGHT + stat + ": " + Style.RESET_ALL + num)

def get_a_domain_report(domain: str):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url=url,headers=headers)
    return response.json()

def file_hash(path: str, chunk_size: int = 8192) -> str:

    h = hashlib.new("sha256")
    with open(path,"rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

def get_file_type(path: str) -> str:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type

def scan_file(path: str, password: str = None) -> str:
    
    url = "https://www.virustotal.com/api/v3/files"

    mime_type = get_file_type(path)
    files = {
        "file": (path, open(path,"rb"), mime_type)
    }
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    if password:
        payload = {"password": password}
        response = requests.post(url=url,headers=headers,payload=payload,files=files)
        return response.json()["data"]["id"]
    
    response = requests.post(url=url,headers=headers,files=files)
    return response.json()["data"]["id"]


def scan_url(url: str) -> str:
    
    target_url = "https://www.virustotal.com/api/v3/urls"
    payload = { "url": url }
    headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY,
            "content-type": "application/x-www-form-urlencoded"
}
    response = requests.post(url=target_url,data=payload,headers=headers)
    if response.status_code == 409:
        print(Fore.RED + Style.BRIGHT + "[!] Conflit Error Ocurs [!]" + Style.RESET_ALL)
        exit(1)
    return response.json()["data"]["id"]

def get_scan_analysis(id: str):
    url = f"https://www.virustotal.com/api/v3/analyses/{id}"
    headers = {
        "accept":"application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url,headers=headers)
    return response.json()

def menu():
    print(Fore.GREEN + Style.BRIGHT + "\t 1) Scan URL")
    print(Fore.GREEN + Style.BRIGHT + "\t 2) File Hash Calculate")
    print(Fore.GREEN + Style.BRIGHT + "\t 3) Scan A File")
    print(Fore.GREEN + Style.BRIGHT + "\t 4) Scan A Domain")
    print(Fore.GREEN + Style.BRIGHT + "\t 5) Help")
    print(Fore.GREEN + Style.BRIGHT + "\t 6) Exit")
    print(Style.RESET_ALL)

def main():
    ascii_banner = pyfiglet.figlet_format("Virus Total Scanner")
    print(Fore.CYAN + Style.BRIGHT + ascii_banner + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + "Made by : Eng. Ezzudin Tomizi" + Style.RESET_ALL)
    print("-"*50+"\n")
    menu()
    while True:
        choice = input(Fore.BLUE + Style.BRIGHT + ":\\> " + Style.RESET_ALL)

        if choice == "1":

            url = input(Fore.BLUE + Style.BRIGHT + ":\\> Enter URL: " + Style.RESET_ALL)
            report_id = scan_url(url)
            report = get_scan_analysis(report_id)
            stats = report["data"]["attributes"]["stats"]
            print_analysis_report(stats=stats)
            
        elif choice == "2":
            path = input(Fore.BLUE + Style.BRIGHT + ":\\> Enter File Path: " + Style.RESET_ALL)
            hashed_file = file_hash(path)
            print(f"The hash value is: {hashed_file}")
        
        elif choice == "3":
            path = input(Fore.BLUE + Style.BRIGHT + ":\\> Enter File Path: " + Style.RESET_ALL)
            password = input(Fore.BLUE + Style.BRIGHT + ":\\> Enter File Password -if exists- : " + Style.RESET_ALL)
            report_id = scan_file(path=path,password=password)
            stats = get_scan_analysis(id=report_id)["data"]["attributes"]["stats"]
            print_analysis_report(stats=stats)

        elif choice == "4":
            console = Console()
            domain = input(Fore.BLUE + Style.BRIGHT + ":\\> Enter The Domain: " + Style.RESET_ALL)
            report = get_a_domain_report(domain=domain)
            stats = report["data"]["attributes"]["last_analysis_stats"]
            print_analysis_report(stats=stats)
            print("\n")
            console.print(Panel(report["data"]["attributes"]["whois"],title="WHOIS Summary"))

        elif choice == "5":
            menu()
        elif choice == "6":
            print(Fore.CYAN + Style.BRIGHT + "[!] See You Next Time :) [!]" + Style.RESET_ALL)
            print(Fore.RED + Style.BRIGHT + "[!] QUITING [!]" + Style.RESET_ALL)
            time.sleep(1)
            exit(1)
        else:
            print(Fore.RED + Style.BRIGHT + "[!] Incorrect Choice [!]" + Style.RESET_ALL)
               


if "__main__" == __name__:
    if not VIRUSTOTAL_API_KEY:
        print(Fore.RED + Style.BRIGHT + "[!] Virus Total API Key Doesn't Exists [!]" + Style.RESET_ALL)   
        exit(1) 
    main()