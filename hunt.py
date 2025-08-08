#!/usr/bin/env python3

"""
Script to assist in investigations by collecting IP data from various sources.
"""

import argparse
from datetime import datetime
import sys
import requests
import shodan
import whois
from dotenv import load_dotenv
import os
import greynoise

# API Keys
# API Keys are required for Shodan, VirusTotal, and Greynoise
# Register with them here:
# https://shodan.io
# https://virustotal.com
# https://viz.greynoise.io
env_file = load_dotenv()
SHODAN_API = os.getenv("SHODAN_API")
VT_API = os.getenv("VT_API")
GREYNOISE_API = os.getenv("GREYNOISE_API")
API_keys = {
    "SHODAN_API": SHODAN_API,
    "VT_API": VT_API,
    "GREYNOISE_API": GREYNOISE_API,
}
# Platforms
ALIENVAULT_OTX = "otx"
GREYNOISE = "greynoise"
IPINFO_IO = "ipinfo"
SHODAN = "shodan"
VIRUSTOTAL = "vt"
WHOIS = "whois"

PLATFORMS = {
    ALIENVAULT_OTX,
    GREYNOISE,
    IPINFO_IO,
    SHODAN,
    VIRUSTOTAL,
    WHOIS,
}
RATELIMITED_PLATFORMS = {
    VIRUSTOTAL,
}
###########################################################
#FUNCTIONS AND MAIN



def main():
    #Initiate the argument parser
    parser= argparse.ArgumentParser(description="Investigate an IP address or Domain for available OSINT.")
    # Add arguments to the parser
    args = process_args(parser)
    # Check if the script is being run with the correct arguments
    preflight_check(args)
    #run functions based on type arguments passed
    run_functions(args)

############################################################
#FUNCTIONS FOR ARGUMENTS AND PRE-FLIGHT CHECKS

def process_args(parser):
    parser.add_argument("-i", "--ipaddress", help="IP to investigate.")
    parser.add_argument("-d", "--domain", help="Domain to investigate.")
    parser.add_argument("-f", "--file", help="File containing a list of IPs")
    # Add argument for API keys
    parser.add_argument("--shodan-api", help="Shodan API key.")
    parser.add_argument("--vt-api", help="VirusTotal API key.")
    parser.add_argument("--greynoise-api", help="GreyNoise API key.")
    # Add argument for platforms
    parser.add_argument("-p", "--platforms", nargs="+", choices=PLATFORMS, help="Platforms to use.")
    args = parser.parse_args()
    return args    





def preflight_check(args):
    '''
    Preflight check to ensure that the script is being run with the correct arguments.
    This includes checking for API keys and valid platforms.
    '''
    #Check IPs and Domains
    if args.ipaddress and args.domain:
        print("Please specify either an IP address or a domain, not both.")
        sys.exit(1)
    if args.ipaddress and args.file:
        print("Please specify either an IP address or a file, not both.")
        sys.exit(1)
    if args.domain and args.file:
        print("Please specify either a domain or a file, not both.")
        sys.exit(1)
    if args.ipaddress and not args.ipaddress.replace(".", "").isdigit():
        print("Invalid IP address.")
        sys.exit(1)
    if args.domain and not args.domain.replace(".", "").isalnum():
        print("Invalid domain.")
        sys.exit(1)
    # Check if API keys are provided
    if not API_keys["SHODAN_API"] and not args.shodan_api:
        print("Shodan API key is required.")
        sys.exit(1)
    if not API_keys["VT_API"] and not args.vt_api:
        print("VirusTotal API key is required.")
        sys.exit(1)
    if not API_keys["GREYNOISE_API"] and not args.greynoise_api:
        print("GreyNoise API key is required.")
        sys.exit(1)
    # Check if platforms are valide and provided
     # Check if the platforms are valid
"""
    if args.platforms:
        for platform in args.platforms:
            if platform not in PLATFORMS:
                print(f"Invalid platform: {platform}.")
                sys.exit(1)
"""
#run functions based on type arguments passed
def run_functions(args):
    """
    Run the appropriate functions based on the arguments passed.
    """
    if args.ipaddress:
        ip_check(args.ipaddress, args.platforms)
    elif args.domain:
        domain_check(args.domain, args.platforms)
    elif args.file:
        targets_processed_count = 0
        is_ratelimited = bool(set(args.platforms).intersection(RATELIMITED_PLATFORMS))
        with open(args.file) as file:
            for target in file:
                if targets_processed_count > 5:
                    print("Stopping due to API ratelimits.")
                    break
                clean = target.strip()
                kind = clean.replace(".", "").replace(":", "").replace("/", "")
                if kind.isdigit():
                    if is_ratelimited:
                        targets_processed_count += 1
                    ip_check(clean, args.platforms)
                elif kind.isalnum():
                    if is_ratelimited:
                        targets_processed_count += 1
                    domain_check(clean, args.platforms)
            else:
                print(f"Skipping {clean}, can't determine the type.") 
    

    # Add argument for output file
    #parser.add_argument("-o", "--output", help="Output file to save results.")

    # Redirect output to file if specified
    #if args.output:
    #    sys.stdout = open(args.output, "w")
    #begin other argument checks 

##############################################################################
# Start of IP Check functions



# Start of Domain Check functions


def ip_check(target, platforms):
    """
    Collection of all IP check functions to run.
    """
    #if IPINFO_IO in platforms:
    geo_info(target)
    #if SHODAN in platforms:
    shodan_check(target)
    #if VIRUSTOTAL in platforms:
    vt_ip_check(target)
    #if ALIENVAULT_OTX in platforms:
    av_otx(target)
    #if GREYNOISE in platforms:
    greynoise(target)


def domain_check(target, platforms):
    """
    Collection of all Domain check functions to run.
    """
    if WHOIS in platforms:
        whois_lookup(target)
    if VIRUSTOTAL in platforms:
        vt_domain_check(target)
    if ALIENVAULT_OTX in platforms:
        av_otx_domain(target)


if __name__ == "__main__":
    main()
