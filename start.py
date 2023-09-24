import os
import platform
import subprocess
import time
import re
from ping3 import ping
from scapy.all import sniff, DNS, DNSQR

# Function to check and install a Python package if not installed
def check_install_package(package_name):
    try:
        import importlib
        importlib.import_module(package_name)
    except ImportError:
        print(f"{package_name} is not installed. Installing...")
        subprocess.run(["pip", "install", package_name])

# Check and install required packages
check_install_package("ping3")
check_install_package("scapy")

# Define the list of strings to search for
strings_to_search = [
    "pfmsqosprod2-0.eastasia.cloudapp.azure.com",
    "pfmsqosprod2-0.northeurope.cloudapp.azure.com",
    "pfmsqosprod2-0.southeastasia.cloudapp.azure.com",
    "pfmsqosprod2-0.brazilsouth.cloudapp.azure.com",
    "pfmsqosprod2-0.eastus2.cloudapp.azure.com",
    "pfmsqosprod2-0.eastus.cloudapp.azure.com",
    "pfmsqosprod2-0.westus.cloudapp.azure.com",
    "pfmsqosprod2-0.centralus.cloudapp.azure.com",
    "pfmsqosprod2-0.westeurope.cloudapp.azure.com",
    "pfmsqosprod2-0.australiaeast.cloudapp.azure.com",
    "pfmsqosprod2-0.japaneast.cloudapp.azure.com",
    "pfmsqosprod2-0.japanwest.cloudapp.azure.com",
    "pfmsqosprod2-0.southcentralus.cloudapp.azure.com",
    "pfmsqosprod2-0.northcentralus.cloudapp.azure.com",
    "pfmsqosprod2-0.uksouth.cloudapp.azure.com",
    "pfmsqosprod2-0.ukwest.cloudapp.azure.com",
    "pfmsqosprod2-0.canadacentral.cloudapp.azure.com",
    "pfmsqosprod2-0.canadaeast.cloudapp.azure.com"
]

# Additional pattern to search for
additional_pattern = r"dns-([a-zA-Z0-9-]+)\.([a-zA-Z0-9-]+)\.cloudapp\.azure\.com"

# Platform-specific console clear command
clear_command = "cls" if platform.system() == "Windows" else "clear"

def clear_console():
    os.system(clear_command)

# Clear the console and provide a notification
clear_console()
print("Scan started...")

# ANSI color codes
GREEN = "\033[32m"  # Green text
YELLOW = "\033[33m"  # Yellow text
RED = "\033[31m"     # Red text
RESET_COLOR = "\033[0m"  # Reset text color

def colorize_ping(ping_ms):
    if 0 <= ping_ms <= 50:
        return f"{GREEN}{ping_ms} ms{RESET_COLOR}"
    elif 51 <= ping_ms <= 80:
        return f"{YELLOW}{ping_ms} ms{RESET_COLOR}"
    else:
        return f"{RED}{ping_ms} ms{RESET_COLOR}"

def dns_sniffer(pkt):
    if DNS in pkt:
        qname = pkt[DNSQR].qname.decode('utf-8')

        for search_string in strings_to_search:
            if search_string in qname:
                print(f"Game server pinged: {search_string}")
                break
        
        match = re.search(additional_pattern, qname)
        if match:
            os.system(clear_command)
            game_id = match.group(1)
            region = match.group(2)
            print("--------------------------------------------------------")
            print(f"\n Game Lobby with ID: {game_id} \n \n Region: {region}\n")
            print("--------------------------------------------------------")
            game_url = f"dns-{game_id}.{region}.cloudapp.azure.com"
            ping_successful = True

            ping_attempts = 3
            total_ping_time = 0

            for _ in range(ping_attempts):
                ping_result = ping(game_url)
                if ping_result is not None:
                    total_ping_time += ping_result
                    ping_result_ms = round(ping_result * 1000, 2)
                    
                    if ping_result_ms < 1:
                        print("Ping:{GREEN}< 1 ms ms{RESET_COLOR}")
                        time.sleep(3)
                    else:
                        colorized_ping = colorize_ping(ping_result_ms)
                        print(f"Ping: {colorized_ping}")
                        time.sleep(3)
                else:
                    print("Ping failed. Reverting to searching...")
                    ping_successful = False

            if ping_successful:
                average_ping_ms = round((total_ping_time / ping_attempts) * 1000, 2)
                colorized_average_ping = colorize_ping(average_ping_ms)
                print(f"Average Ping: {colorized_average_ping}")

                while True:
                    user_input = input("Press Enter to continue searching or 'q' to quit: ")
                    if user_input.lower() == 'q':
                        print("Exiting...")
                        exit()
                    elif user_input == '':
                        print("Continuing search...")
                        break

try:
    sniff(filter="udp port 53", prn=dns_sniffer, store=0)
except Exception as e:
    if "winpcap is not installed" in str(e):
        os.system(clear_command)
        print("Error: WinPcap is not installed. Please install WinPcap or a similar packet capture library to run this script.")
    else:
        raise e
