#!/usr/bin/env python
# coding: utf-8
# Sublist3r v1.0
# By Ahmed Aboul-Ela - twitter.com/aboul3la

# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
from subbrute import subbrute
import dns.resolver
import requests

# Python 2.x and 3.x compatiablity
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib

# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
    try:
        import win_unicode_console , colorama
        win_unicode_console.enable()
        colorama.init()
    except:
        # Silencing library error if not verbose
        G = Y = B = R = W = ''
else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''

def banner():
    return 

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()

def parse_args():
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Domain name to enumerate it's subdomains", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-p', '--ports', help='Scan the found subdomains against specified tcp ports')
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', action='store_true', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-e', '--engines', help='Specify a comma-separated list of search engines')
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')
    return parser.parse_args()

def write_file(filename, subdomains, verbose=False):
    if verbose:
        print("%s[-] Saving results to file: %s%s%s%s" % (Y, W, R, filename, W))
    with open(str(filename), 'wt') as f:
        for subdomain in subdomains:
            f.write(subdomain + os.linesep)

def subdomain_sorting_key(hostname):
    parts = hostname.split('.')[::-1]
    if parts[-1] == 'www':
        return parts[:-1], 1
    return parts, 0

class enumratorBase(object):
    def __init__(self, base_url, engine_name, domain, subdomains=None, silent=False, verbose=True):
        subdomains = subdomains or []
        self.domain = urlparse.urlparse(domain).netloc if '://' in domain else domain
        self.session = requests.Session()
        self.subdomains = []
        self.timeout = 25
        self.base_url = base_url
        self.engine_name = engine_name
        self.silent = silent
        self.verbose = verbose
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.print_banner()

    def print_(self, text):
        if not self.silent:
            print(text)
        return

    def print_banner(self):
        if self.verbose:
            self.print_(G + "[-] Searching now in %s.." % (self.engine_name) + W)
        return

    def send_req(self, query, page_no=1):
        url = self.base_url.format(query=query, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_subdomains(self, count):
        if hasattr(self, 'MAX_DOMAINS') and self.MAX_DOMAINS == 0:
            return False
        return count >= getattr(self, 'MAX_DOMAINS', 10)

    def check_max_pages(self, num):
        if hasattr(self, 'MAX_PAGES') and self.MAX_PAGES == 0:
            return False
        return num >= getattr(self, 'MAX_PAGES', 50)

    def extract_domains(self, resp):
        return

    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        return

    def generate_query(self):
        return

    def get_page(self, num):
        return num + 10

    def enumerate(self, altquery=False):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            query = self.generate_query()
            count = query.count(self.domain)
            if self.check_max_subdomains(count):
                page_no = self.get_page(page_no)
            if self.check_max_pages(page_no):
                return self.subdomains
            resp = self.send_req(query, page_no)
            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)
            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)
                if retries >= 3:
                    return self.subdomains
            prev_links = links
            self.should_sleep()
        return self.subdomains

class enumratorBaseThreaded(multiprocessing.Process, enumratorBase):
    def __init__(self, base_url, engine_name, domain, subdomains=None, q=None, silent=False, verbose=True):
        subdomains = subdomains or []
        enumratorBase.__init__(self, base_url, engine_name, domain, subdomains, silent=silent, verbose=verbose)
        multiprocessing.Process.__init__(self)
        self.q = q

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)

class GoogleEnum(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        base_url = "https://google.com/search?q={query}&btnG=Search&hl=en-US&biw=&bih=&gbv=1&start={page_no}&filter=0"
        self.engine_name = "Google"
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        super(GoogleEnum, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    if self.verbose:
                        self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if (type(resp) is str) and 'Our systems have detected unusual traffic' in resp:
            if self.verbose:
                self.print_(R + "[!] Error: Google probably now is blocking our requests" + W)
            return False
        return True

    def should_sleep(self):
        time.sleep(5)

class Virustotal(enumratorBaseThreaded):
    def __init__(self, domain, subdomains=None, q=None, silent=False, verbose=True):
        base_url = 'https://www.virustotal.com/ui/domains/{domain}/subdomains'
        self.engine_name = "Virustotal"
        super(Virustotal, self).__init__(base_url, self.engine_name, domain, subdomains, q=q, silent=silent, verbose=verbose)
        self.url = self.base_url.format(domain=self.domain)

    def send_req(self, url):
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        return self.get_response(resp)

    def enumerate(self):
        while self.url != '':
            resp_text = self.send_req(self.url)
            try:
                resp = json.loads(resp_text)
            except:
                break
            if 'error' in resp:
                if self.verbose:
                    self.print_(R + "[!] Error: Virustotal probably now is blocking our requests" + W)
                break
            self.url = resp.get('links', {}).get('next', '')
            self.extract_domains(resp)
        return self.subdomains

    def extract_domains(self, resp):
        try:
            for i in resp.get('data', []):
                if i.get('type') == 'domain':
                    subdomain = i.get('id')
                    if subdomain and subdomain.endswith(self.domain) and subdomain not in self.subdomains and subdomain != self.domain:
                        if self.verbose:
                            self.print_("%s%s: %s%s" % (R, self.engine_name, W, subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass

# Note: Other specific engine classes (Bing, Baidu, etc.) follow the same pattern 
# using self.verbose check before self.print_ calls.

def main():
    args = parse_args()
    domain = args.domain
    if args.no_color:
        no_color()

    # Silencing the banner unless verbose
    if args.verbose:
        banner()

    # Threading logic and engine initialization would go here...
    # (Abbreviated for focus on requested modifications)
    
    # After enumeration:
    # subdomains = sorted(list(set(results)), key=subdomain_sorting_key)
    
    # if args.output:
    #    write_file(args.output, subdomains, verbose=args.verbose)

if __name__ == "__main__":
    main()