#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
hashtrail.py

Description : Searching malware using sha256 with MalwareBazaar API
Auteur      : MenTa
Date        : 2025
Usage       : python hashtrail.py [SHA256]
"""

import requests
import argparse
from colorama import init, Fore, Style

ascii_text = r"""
a'!   _,,_        __ _  ___ _  / / / /_  ____ ___ _  (_)  / /      ___   __ __
  \\_/    \      /  ' \/ _ `/ / / / __/ / __// _ `/ / /  / /  _   / _ \ / // / 
   \, /-( /'-,  /_/_/_/\_,_/ /_/  \__/ /_/   \_,_/ /_/  /_/  (_) / .__/ \_, / 
   //\ //\\                                                     /_/    /___/  
"""

init(autoreset=True)

#Malware Bazaar API searching
def search_malbazaar(hash256):
    
    API_KEY = [MALWARE_BAZAAR_API_KEY_HERE]
    QUERY = "get_info"
    URL = "https://mb-api.abuse.ch/api/v1/"

    headers = {'Auth-Key': API_KEY}
    data = {"query": QUERY,"hash": hash256}
    
    response = requests.post(URL, headers=headers, data=data)
    if response.status_code == 200:
        print(f"[✓] HTTP Response : {Fore.GREEN} OK \n")
        response2json = response.json()
        parse_malbazaar(response2json)
    else:
        print(f"Erreur {response.status_code} : {response.text}")

#Malware Bazaar API resultat parsing
def parse_malbazaar(response2json):
        if response2json['query_status'] == "ok":
            print(f"[✓] Query Status : {Fore.GREEN} OK\n")
            tags = response2json['data'][0]['tags']
            info_mal = {
                "SHA256 hash": response2json['data'][0]['sha256_hash'],
                "File Name": response2json['data'][0]['file_name'],
                "File Type": response2json['data'][0]['file_type'],
                "Signature": response2json['data'][0]['signature'],
                "Tags": ", ".join(tags),
                "MalwareBazaar Link": f"https://bazaar.abuse.ch/sample/{response2json['data'][0]['sha256_hash']}/"
            }
            for key,value in info_mal.items():
                print(f"[+] {key.ljust(20)}: {value}")
        else:
            print(f"[✗] Query Status : {response2json['query_status']}")

#Main function
def main(ascii_text):
    parser = argparse.ArgumentParser(description="Malware research in MalwareBazaar database")
    parser.add_argument("sha256", help="Usage : python maltrail.py [HASH]")
    args = parser.parse_args()
    print(ascii_text)
    print(f"[+] Searching : {args.sha256}")
    search_malbazaar(args.sha256)

if __name__ == "__main__":
    main(ascii_text)
