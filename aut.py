import subprocess
import requests
from bs4 import BeautifulSoup
import re

def target_identification(target_url):
    ip_addresses = subprocess.getoutput(f"nslookup {target_url} | grep 'Address' | grep -v '#'")
    print("IP Addresses:")
    print(ip_addresses)

    subdomains = subprocess.getoutput(f"amass enum -d {target_url}")
    print("Subdomains:")
    print(subdomains)

    dir_enum_output = subprocess.getoutput(f"gobuster dir -u {target_url} -w /")
    print("Directory Enumeration:")
    print(dir_enum_output)

    virtual_hosts = subprocess.getoutput(f"curl -I {target_url} | grep 'Host'")
    print("Virtual Hosts:")
    print(virtual_hosts)

    def crawl_website(url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [link.get('href') for link in soup.find_all('a', href=True)]
            return links
        except Exception as e:
            print(f"Error while crawling {url}: {str(e)}")
            return []

    links = crawl_website(target_url)
    print("Discovered Links:")
    print(links)

    def scan_for_vulnerabilities(url):
        try:
            subprocess.run(["zap-cli", "quick-scan", "-l", url])
            subprocess.run(["zap-cli", "report", "-o", "zap_report.html", "-f", "html"])
        except Exception as e:
            print(f"Error during vulnerability scanning with OWASP ZAP: {str(e)}")

    scan_for_vulnerabilities(target_url)
    print("Vulnerability scanning completed with OWASP ZAP. Check zap_report.html for results.")

    def generate_report(target, ip_addresses, subdomains, dir_enum_output, virtual_hosts, links, vulnerabilities):
            report = f"Web Pentest Report for {target}\n"
            report += f"IP Addresses: {ip_addresses}\n"
            report += f"Subdomains: {subdomains}\n"
            report += f"Directory Enumeration: {dir_enum_output}\n"
            report += f"Virtual Hosts: {virtual_hosts}\n"
            report += f"Discovered Links: {links}\n"
            report += f"Vulnerabilities: {vulnerabilities}\n"

            with open("pentest_report.txt", "w") as report_file:
                report_file.write(report)

            print("Report generated: pentest_report.txt")

    generate_report(target_url, ip_addresses, subdomains, dir_enum_output, virtual_hosts, links)


def scan_and_enum(target_ip,target_url):

    def network_scan(target_ip):
        try:
            nmap_output = subprocess.getoutput(f"nmap -sP -p 1-65535 {target_ip}")
            print("Network Scan Output:")
            print(nmap_output)
        except Exception as e:
            print(f"Error during network scan: {str(e)}")
    network_scan(target_ip)

    def web_technology_enum(target_url):
        try:
            whatweb_output = subprocess.getoutput(f"whatweb {target_url}")
            print("Web Technology Enumeration Output:")
            print(whatweb_output)
        except Exception as e:
            print(f"Error during web technology enumeration: {str(e)}")
    web_technology_enum(target_url)
    def web_app_crawling(target_url):
        try:
            gobuster_output = subprocess.getoutput(f"gobuster dir -u {target_url} -w /")
            print("Web App Crawling Output:")
            print(gobuster_output)
        except Exception as e:
            print(f"Error during web app crawling: {str(e)}")
    web_app_crawling(target_url)
if __name__ == "__main__":
    target_ip = input()
    target_url = input()
    target_identification(target_url)
    scan_and_enum(target_ip,target_url)
