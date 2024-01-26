import subprocess
import requests
from bs4 import BeautifulSoup
import re

def target_identification(target_url):
    ip_addr = subprocess.getoutput(f"nslookup {target_url} | grep 'Address' | grep -v '#'")
    print("IP Addresses:")
    print(ip_addr)

    subdomains = subprocess.getoutput(f"amass enum -d {target_url}")
    print("Subdomains:")
    print(subdomains)

    dir_enum_op = subprocess.getoutput(f"gobuster dir -u {target_url} -w /")
    print("Directory Enumeration:")
    print(dir_enum_op)

    virtual_hosts = subprocess.getoutput(f"curl -I {target_url} | grep 'Host'")
    print("Virtual Hosts:")
    print(virtual_hosts)


if __name__ == "__main__":

    target_url = input()
    target_identification(target_url)
