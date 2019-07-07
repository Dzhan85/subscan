#!/usr/bin/env python
# coding: utf-8
import argparse
import dns.resolver
import sys
import requests
import json
import difflib
import os
import re
import psycopg2
from tld import get_fld
from tld.utils import update_tld_names
from termcolor import colored
import threading
is_py2 = sys.version[0] == "2" #checks if python version used == 2 in order to properly handle import of Queue module depending on the version used.
if is_py2:
    import Queue as queue
else:
    import queue as queue
from config import *
import time

#version = "1.0.0"
requests.packages.urllib3.disable_warnings()

def banner():
    print(colored('''
 #####  #     # #######    ######  ######   #####  
#     # ##    # #          #     # #     # #     # 
#       # #   # #          #     # #     #       # 
 #####  #  #  # #####      ######  ######   #####  
      # #   # # #          #   #   #       #       
#     # #    ## #          #    #  #       #       
 #####  #     # #######    #     # #       ####### 
                                                   
    ''', "yellow"))
    print(colored("             SNE RP2 project", "green"))
    print(colored("                           Version: {}", "green").format(version))

def parse_args():
        parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument('-u',
                            dest = "target",
                            help = "Domain to add. E.g: test.com",
                            required = False)
        parser.add_argument('-d', 
                            dest = "remove_domain",
                            help = "Domain to remove from the monitored list. E.g: yahoo.com",
                            required = False)
        parser.add_argument('-t', 
                            dest = "threads",
                            help = "Number of concurrent threads to use.",
                            type = int,
                            default = 20)
        parser.add_argument('-r', 
                            dest = "resolve",
                            help = "Perform DNS resolution.",
                            required=False,
                            nargs='?',
                            const="True")
        parser.add_argument('-a',
                            dest = "listing",
                            help = "Listing all monitored domains.",
                            required =  False,
                            nargs='?',
                            const="True")
        parser.add_argument('-m', 
                            dest = "reset",
                            help = "Reset everything.",
                            nargs='?',
                            const="True")
        return parser.parse_args()

def domain_sanity_check(domain): #Verify the domain name sanity
    if domain:
        try:
            domain = get_fld(domain, fix_protocol = True)
            return domain
        except:
            print(colored("[!] Incorrect domain format.Ex: example.com, http(s)://example.com, www.example.com", "red"))
            sys.exit(1)
    else:
        pass

def reset(do_reset): #clear the monitored list of domains and remove all locally stored files
    if do_reset:
        os.system("cd ./output/ && rm -f *.txt && cd .. && rm -f example.com && touch example.com  ")
        print(colored("\n[!] Reset  was successfully. Please add new domains!", "blue"))
        sys.exit(1)
    else: pass

def remove_domain(domain_to_delete): #remove a domain from the monitored list
    new_list = []
    if domain_to_delete:
        with open("example.com", "r") as domains:
            for line in domains:
                line = line.replace("\n", "")
                if line in domain_to_delete:
                    os.system("rm -f ./output/{}.txt".format(line))
                    print(colored("\n[-] {} was successfully removed from the  list.".format(line), "green"))
                else:
                    new_list.append(line)
        os.system("rm -f example.com")
        with open("example.com", "w") as new_file:
            for i in new_list:
                new_file.write(i + "\n")
        sys.exit(1)

def domains_listing(): #list all the monitored domains
    global list_domains
    if list_domains:
        print(colored("\n[*] Below is the list of saved domain names:\n", "green"))
        with open("example.com", "r") as monitored_list:
            for domain in monitored_list:
                print(colored("{}".format(domain.replace("\n", "")), "yellow"))
        sys.exit(1)

class cert_database(object): #Connecting to crt.sh public API to retrieve subdomains
    global enable_logging
    def lookup(self, domain, wildcard = True):
        try:
            try: #connecting to crt.sh postgres database to retrieve subdomains.
                unique_domains = set()
                domain = domain.replace('%25.', '')
                conn = psycopg2.connect("dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
                conn.autocommit = True
                cursor = conn.cursor()
                cursor.execute("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(domain))
                for result in cursor.fetchall():
                    matches = re.findall(r"\'(.+?)\'", str(result))
                    for subdomain in matches:
                        try:
                            if get_fld("https://" + subdomain) == domain:
                                unique_domains.add(subdomain.lower())
                        except: pass
                return sorted(unique_domains)
            except:
                error = "Unable to connect to the database. We will attempt to use the API instead."
                errorlog(error, enable_logging)
        except:
            base_url = "https://crt.sh/?q={}&output=json"
            if wildcard:
                domain = "%25.{}".format(domain)
                url = base_url.format(domain)
            subdomains = set()
            user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:64.0) Gecko/20100101 Firefox/64.0'
            req = requests.get(url, headers={'User-Agent': user_agent}, timeout=20, verify=False) #times out after 8 seconds waiting
            if req.status_code == 200:
                try:
                    content = req.content.decode('utf-8')
                    data = json.loads(content)
                    for subdomain in data:
                        subdomains.add(subdomain["name_value"].lower())
                    return sorted(subdomains)
                except:
                    error = "Error retrieving information for {}.".format(domain.replace('%25.', ''))
                    errorlog(error, enable_logging)

def queuing(): #using the queue for multithreading purposes
    global domain_to_monitor
    global q1
    global q2
    q1 = queue.Queue(maxsize=0)
    q2 = queue.Queue(maxsize=0)
    if domain_to_monitor:
        pass
    elif os.path.getsize("domains.txt") == 0:
        print(colored("[!] Please consider adding a list of domains to monitor first.", "red"))
        sys.exit(1)
    else:
        with open("domains.txt", "r") as targets:
            for line in targets:
                if line != "":
                    q1.put(line.replace('\n', ''))
                    q2.put(line.replace('\n', ''))
                else: pass

def adding_new_domain(q1): #adds a new domain to the monitoring list
    unique_list = []
    global domain_to_monitor
    global input
    if domain_to_monitor:
        if not os.path.isfile('./domains.txt'): #check if domains.txt exist, if not create a new one
            os.system("touch domains.txt")
        else: pass
        with open("domains.txt", "r+") as domains: #checking domain name isn't already monitored
            for line in domains:
                if domain_to_monitor == line.replace('\n', ''):
                    print(colored("[!] The domain name {} is already being monitored.".format(domain_to_monitor), "red"))
                    sys.exit(1)
            response = cert_database().lookup(domain_to_monitor)
            with open("./output/" + domain_to_monitor.lower() + ".txt", "a") as subdomains: #saving a copy of current subdomains
                for subdomain in response:
                    subdomains.write(subdomain + "\n")
            with open("domains.txt", "a") as domains: #fetching subdomains if not monitored
                domains.write(domain_to_monitor.lower() + '\n')
                print(colored("\n[+] Adding {} to the  list of domains.\n".format(domain_to_monitor), "blue"))
            try: input = raw_input #fixes python 2.x and 3.x input keyword
            except NameError: pass
            choice = input(colored("[?] Do you wish to list subdomains found for {}? [Y]es [N]o (default: [N]) ".format(domain_to_monitor), "blue")) #listing subdomains upon request
            if choice.upper() == "Y":
                if response:
                    for subdomain in response:
                        unique_list.append(subdomain)
                    unique_list = list(set(unique_list))
                    for subdomain in unique_list:
                        print(colored(subdomain, "yellow"))
                else:
                    print(colored("\n[!] Unfortunately, we couldn't find any subdomain for {}".format(domain_to_monitor), "red"))
            else:
                sys.exit(1)
    else: #checks if a domain is monitored but has no text file saved in ./output
                try:
                    line = q1.get(timeout=10)
                    if not os.path.isfile("./output/" + line.lower() + ".txt"):
                        response = cert_database().lookup(line)
                        if response:
                            with open("./output/" + line.lower() + ".txt", "a") as subdomains:
                                for subdomain in response:
                                    subdomains.write(subdomain + "\n")
                        else: pass
                    else: pass
                except queue.Empty:
                    pass

def check_new_subdomains(q2): #retrieves new list of subdomains and stores a temporary text file for comparaison purposes
    global domain_to_monitor
    global domain_to_delete
    if domain_to_monitor is None:
        if domain_to_delete is None:
            try:
                line = q2.get(timeout=10)
                print("[*] Checking {}".format(line))
                with open("./output/" + line.lower() + "_tmp.txt", "a") as subs:
                    response = cert_database().lookup(line)
                    if response:
                        for subdomain in response:
                            subs.write(subdomain + "\n")
            except queue.Empty:
                pass
    else: pass

def compare_files_diff(domain_to_monitor): #compares the temporary text file with previously stored copy to check if there are new subdomains
    global enable_logging
    if domain_to_monitor is None:
        if domain_to_delete is None:
            result = []
            with open("domains.txt", "r") as targets:
                for line in targets:
                    domain_to_monitor = line.replace('\n', '')
                    try:
                        file1 = open("./output/" + domain_to_monitor.lower() + '.txt', 'r')
                        file2 = open("./output/" + domain_to_monitor.lower() + '_tmp.txt', 'r')
                        diff = difflib.ndiff(file1.readlines(), file2.readlines())
                        changes = [l for l in diff if l.startswith('+ ')] #check if there are new items/subdomains
                        newdiff = []
                        for c in changes:
                            c = c.replace('+ ', '')
                            c = c.replace('*.', '')
                            c = c.replace('\n', '')
                            result.append(c)
                            result = list(set(result)) #remove duplicates
                    except:
                        error = "There was an error opening one of the files: {} or {}".format(domain_to_monitor + '.txt', domain_to_monitor + '_tmp.txt')
                        errorlog(error, enable_logging)
                        os.system("rm -f ./output/{}".format(line.replace('\n','') + "_tmp.txt"))
                return(result)

def dns_resolution(new_subdomains): #Perform DNS resolution on retrieved subdomains
    dns_results = {}
    subdomains_to_resolve = new_subdomains
    print(colored("\n[!] Performing DNS resolution. Please do not interrupt!", "red"))
    for domain in subdomains_to_resolve:
        domain = domain.replace('+ ','')
        domain = domain.replace('*.','')
        dns_results[domain] = {}
        try:
            for qtype in ['A','CNAME']:
                dns_output = dns.resolver.query(domain,qtype, raise_on_no_answer = False)
                if dns_output.rrset is None:
                    pass
                elif dns_output.rdtype == 1:
                    a_records = [str(i) for i in dns_output.rrset]
                    dns_results[domain]["A"] = a_records
                elif dns_output.rdtype == 5:
                    cname_records = [str(i) for i in dns_output.rrset]
                    dns_results[domain]["CNAME"] = cname_records
                else: pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            dns_results[domain]["A"] = eval('["Timed out while resolving."]')
            dns_results[domain]["CNAME"] = eval('["Timed out error while resolving."]')
            pass
        except dns.exception.DNSException:
            dns_results[domain]["A"] = eval('["There was an error while resolving."]')
            dns_results[domain]["CNAME"] = eval('["There was an error while resolving."]')
            pass
    if dns_results:
        return posting_to_slack(None, True, dns_results) #Slack new subdomains with DNS ouput
    else:
        return posting_to_slack(None, False, None) #Nothing found notification

def multithreading(threads):
    global domain_to_monitor
    threads_list = []
    if not domain_to_monitor:
        num = sum(1 for line in open("domains.txt")) #minimum threads executed equals the number of monitored domains
        for i in range(max(threads, num)):
            if not (q1.empty() and q2.empty()):
                t1 = threading.Thread(target = adding_new_domain, args = (q1, ))
                t2 = threading.Thread(target = check_new_subdomains, args = (q2, ))
                t1.start()
                t2.start()
                threads_list.append(t1)
                threads_list.append(t2)
    else:
        adding_new_domain(domain_to_monitor)

    for t in threads_list:
        t.join()

if __name__ == '__main__':

#parse arguments
    dns_resolve = parse_args().resolve
    #enable_logging = parse_args().logging
    list_domains = parse_args().listing
    domain_to_monitor = domain_sanity_check(parse_args().target)
    domain_to_delete = domain_sanity_check(parse_args().remove_domain)
    do_reset = parse_args().reset

#execute the various functions
    banner()
    reset(do_reset)
    remove_domain(domain_to_delete)
    domains_listing()
    queuing()
    multithreading(parse_args().threads)
    new_subdomains = compare_files_diff(domain_to_monitor)

# Check if DNS resolution is checked
    if not domain_to_monitor:
        if (dns_resolve and new_subdomains):
            dns_resolution(new_subdomains)
        else:
            posting_to_slack(new_subdomains, False, None)
    else: pass