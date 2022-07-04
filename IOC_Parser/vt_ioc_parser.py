"""
Uses VT API to check for malicious detections against list of IPv4, domain, and hash IOCs
"""

import sys
import os
import re
import time
from math import ceil

import requests
import json
import pandas as pd

from datetime import datetime as dt, timedelta
import argparse


def init_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('infile', help='file to ingest')
    parser.add_argument('-p', '--passive_dns', help='passive DNS records to test if IP is shared hosting', action='store_true')
    parser.add_argument('-f', '--files', help='pull in threat mapping for communicating files', action='store_true')
    parser.add_argument('-c', '--comments', help='pull in threat mapping for communicating files', action='store_true')
    parser.add_argument('-a', '--abuseipdb', help='ingest AbuseIPDB confidence scores', action='store_true')
    return parser.parse_args()


def file_check(file):
    """Checks if a file name string is a valid file. If not, asks for retry"""
    while not os.path.isfile(file):
        file = input("That filename didn't work, please enter another one: ")

    return file


def ingest_file():
    """check if file arg was given. If not, ask for one."""
    if len(sys.argv) > 1:
        file = file_check(args.infile)
    else:
        print(r'Usage: python .\vt_ioc_parser.py [ file to parse ]')
        file = file_check(input("Which file should we use? "))

    return file


def extract_iocs(file):
    """
    Given a text file (not unicode) that can be read normally, extract all valid IOCs
    """
    with open(file, encoding='latin-1') as f:
        contents = f.read().replace('[.]', '.')  # refang IOCs and domains if defanged

    ip_pattern = re.compile(r'(?:2(?:[0-4]\d|5[0-5])|1?\d{1,2})(?:\.(?:2(?:[0-4]\d|5[0-5])|1?\d{1,2})){3}')
    domain_pattern = re.compile(r'(?:[\w\d]+\.)+[a-zA-Z]+')
    hash_pattern = re.compile(r'[A-Fa-f0-9]{32,}') # will sometimes generate FPs on DGA subdomains
    ips = list(set(re.findall(ip_pattern, contents)))
    domains = list(set(re.findall(domain_pattern, contents)))
    hashes = list(set(re.findall(hash_pattern, contents)))

    ioc_dict = {}
    if ips:
        ioc_dict['ip_addresses'] = ips
    if hashes:
        ioc_dict['files'] = hashes
    if domains:
        ioc_dict['domains'] = domains
    return ioc_dict


def vt_check(ioc, api_type, key, sleep=0.0):
    time.sleep(sleep)  # provide delay to avoid breaking rate limit
    url = f'https://www.virustotal.com/api/v3/{api_type}/{ioc}'
    headers = {'X-Apikey': key}
    return requests.get(url, headers=headers).json().get('data')


def vt_passive_dns(addr, key, sleep=0.0):
    time.sleep(sleep)  # provide delay to avoid breaking rate limit
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{addr}/resolutions'
    headers = {'X-Apikey': key}
    return requests.get(url, headers=headers).json().get('data')


def vt_comments(ioc, api_type, key, sleep=0.0):
    time.sleep(sleep)  # provide delay to avoid breaking rate limit
    url = f'https://www.virustotal.com/api/v3/{api_type}/{ioc}/comments'
    headers = {'X-Apikey': key}
    data = requests.get(url, headers=headers).json().get('data')
    if data:
        return [i.get('attributes').get('text') for i in data]
    return list()


def vt_commfiles(ioc, api_type, key, sleep=0.0):
    time.sleep(sleep)  # provide delay to avoid breaking rate limit
    url = f'https://www.virustotal.com/api/v3/{api_type}/{ioc}/communicating_files'
    headers = {'X-Apikey': key}
    data = requests.get(url, headers=headers).json().get('data')
    if data:
        classifications = {}
        for i in data:
            classification = i.get('attributes').get('popular_threat_classification')
            if classification:
                threat_label = classification.get('suggested_threat_label')
                if threat_label:
                    if threat_label in classifications:
                        classifications[threat_label] += 1
                    else:
                        classifications[threat_label] = 1
        return dict(sorted(classifications.items(), key=lambda x: x[1], reverse=True))
    return dict()
    
    
def abuse_data(ip, key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    querystring = {
    'ipAddress': ip,
    'maxAgeInDays': '90'
    }

    headers = {
    'Accept': 'application/json',
    'Key': key
    }

    response = requests.get(url=url, headers=headers, params=querystring).json()
    
    if response.get('data'):
        return response.get('data').get('abuseConfidenceScore'), response.get('data').get('usageType')
    

if __name__ == "__main__":

    args = init_argparse()

    script_dir = os.path.abspath(os.path.dirname(__file__)) # obtain path of current
    with open(os.path.join(script_dir, 'config.json')) as f:  # load API keys from file
        config = json.load(f)

    try:
        vt_key = config['virustotal']['key']
        rate_limit = config['virustotal']['rate_limit_min']
        sleep_time = ceil((60 / rate_limit * 10)) / 10  # time.sleep() uses seconds. get the largest tenth of a second
        # sleep_time *= 1.5  # give it some additional buffer
    except Exception as e:
        print(e,'\n')
        print('Make sure your config fie has the proper VT key and rate limiting set!\n')
        sys.exit(1)

    ioc_file = ingest_file()
    outfile = f'{".".join(ioc_file.split(".")[:-1])}_parsed.xlsx'
    iocs = extract_iocs(ioc_file)

    passive_window = 730  # days to consider passive DNS records from VT
    cutoff = dt.now() - timedelta(days=passive_window)

    data = {}

    if 'ip_addresses' in iocs:
        ipv4 = {ip: {} for ip in iocs.get('ip_addresses')}
        if args.abuseipdb and len(ipv4) < 1000:
            abuse = True
            try:
                abuse_key = config['abuseipdb']['key']
            except Exception as e:
                print(e, '\n')
                print('Make sure your config fie has the proper AbuseIPDB key!\n')
                sys.exit(1)
        else:
            abuse = False
            print("[-] Warning! skipping AbuseIPDB query as number of IPs exceeds 1k rate limit.")
        
        for ip in ipv4:
            print(f'[+] Checking {ip}...')

            if abuse:
                abuse_score, abuse_usage = abuse_data(ip, abuse_key)
                ipv4[ip]['AbuseIPDB Score'] = abuse_score
                ipv4[ip]['AbuseIPDB Usage Type'] = abuse_usage

            # generic check first
            # failsafe values
            ipv4[ip]['malicious'] = 0
            ipv4[ip]['suspicious'] = 0
            ipv4[ip]['total'] = 0
            ipv4[ip]['country'] = None
            ipv4[ip]['owner'] = None

            vt_data = vt_check(ip, 'ip_addresses', vt_key, sleep=sleep_time)
            if vt_data:
                attrs = vt_data.get('attributes')
                if attrs:
                    detections = attrs.get('last_analysis_stats')
                    if detections:
                        ipv4[ip]['malicious'] = detections.get('malicious', 0)
                        ipv4[ip]['suspicious'] = detections.get('suspicious', 0)
                        ipv4[ip]['total'] = ipv4[ip]['malicious'] + ipv4[ip]['suspicious']

                    ipv4[ip]['country'] = attrs.get('country')
                    ipv4[ip]['owner'] = attrs.get('as_owner')

                    # passive DNS for shared hosting check
                    if args.passive_dns:
                        # failsafe values
                        ipv4[ip]['recent_resolutions'] = list()
                        ipv4[ip]['parent_domains'] = list()
                        ipv4[ip]['likely_shared_hosting'] = False

                        passive_dns = vt_passive_dns(ip, vt_key, sleep=sleep_time)
                        if passive_dns:
                            pdns_filtered = [i.get('attributes').get('host_name') for i in passive_dns
                                             if dt.fromtimestamp(i.get('attributes').get('date')) > cutoff]
                            ipv4[ip]['recent_resolutions'] = pdns_filtered
                            ipv4[ip]['parent_domains'] = list(set(['.'.join(i.split('.')[-2:]) for i in pdns_filtered]))

                            if args.abuseipdb:
                                if ipv4[ip]['AbuseIPDB Usage Type'] == 'Data Center/Web Hosting/Transit':
                                    ipv4[ip]['likely_shared_hosting'] = len(ipv4[ip]['parent_domains']) > 1
                            else:
                                ipv4[ip]['likely_shared_hosting'] = len(ipv4[ip]['parent_domains']) > 1

                    if args.files:
                        ipv4[ip]['communicating_files'] = dict()
                        ipv4[ip]['communicating_files'] = vt_commfiles(ip, 'ip_addresses', vt_key, sleep=sleep_time)

                    if args.comments:
                        ipv4[ip]['comments'] = list()
                        ipv4[ip]['comments'] = vt_comments(ip, 'ip_addresses', vt_key, sleep=sleep_time)
                    

        ip_df = pd.DataFrame.from_dict(ipv4, orient='index').reset_index() \
            .rename(columns={'index': 'ipv4_address'}).sort_values('total', ascending=False)
        data['ip_addresses'] = ip_df

    if 'domains' in iocs:
        domains = {domain: {} for domain in iocs.get('domains')}
        for domain in domains:
            print(f'[+] Checking {domain}...')

            # failsafe values
            domains[domain]['malicious'] = 0
            domains[domain]['suspicious'] = 0
            domains[domain]['total'] = 0
            domains[domain]['associated_ipv4s'] = list()
            domains[domain]['status'] = 'not found'
            domains[domain]['expiration_date'] = 'not found'
            domains[domain]['registrar'] = 'not found'

            vt_data = vt_check(domain, 'domains', vt_key, sleep=sleep_time)
            if vt_data:
                attrs = vt_data.get('attributes')
                if attrs:
                    detections = attrs.get('last_analysis_stats')
                    domains[domain]['malicious'] = detections.get('malicious', 0)
                    domains[domain]['suspicious'] = detections.get('suspicious', 0)
                    domains[domain]['total'] = domains[domain]['malicious'] + domains[domain]['suspicious']

                    resolutions = attrs.get('last_dns_records')
                    if resolutions:
                        domains[domain]['associated_ipv4s'] = [res.get('value') for res
                                                               in resolutions if res.get('type') == 'A']

                    whois = attrs.get('whois')
                    if whois:
                        try:
                            domains[domain]['status'] = re.findall("(?<=Domain Status: )(.*?)(?= http|$|\\n)", whois)[0]
                        except Exception as e:
                            pass
                        try:
                            domains[domain]['expiration_date'] = re.findall("(?<=Expiry Date: )(.*?)(?=T|$|\\n)", whois)[0]
                        except Exception as e:
                            pass
                        try:
                            domains[domain]['registrar'] = re.findall("(?<=Registrar: )(.*?)(?=\\n|$)", whois)[0]
                        except Exception as e:
                            pass

                    if args.files:
                        domains[domain]['communicating_files'] = dict()
                        domains[domain]['communicating_files'] = vt_commfiles(domain, 'domains', vt_key, sleep=sleep_time)

                    if args.comments:
                        domains[domain]['comments'] = list()
                        domains[domain]['comments'] = vt_comments(domain, 'domains', vt_key, sleep=sleep_time)

        domain_df = pd.DataFrame.from_dict(domains, orient='index').reset_index() \
            .rename(columns={'index': 'domain'}).sort_values('total', ascending=False)
        data['domains'] = domain_df

    if 'files' in iocs:
        files = {file: {} for file in iocs.get('files')}
        for file in files:
            print(f'[+] Checking {file}...')

            # failsafe values
            files[file]['malicious'] = 0
            files[file]['suspicious'] = 0
            files[file]['total'] = 0
            files[file]['file_type'] = None
            files[file]['size_kb'] = None
            files[file]['suggested_label'] = 'Not found'
            files[file]['observed_names'] = 'Not found'

            vt_data = vt_check(file, 'files', vt_key, sleep=sleep_time)

            if vt_data:
                attrs = vt_data.get('attributes')
                if attrs:
                    detections = attrs.get('last_analysis_stats')
                    files[file]['malicious'] = detections.get('malicious', 0)
                    files[file]['suspicious'] = detections.get('suspicious', 0)
                    files[file]['total'] = files[file]['malicious'] + files[file]['suspicious']

                    try:
                        files[file]['file_type'] = attrs.get('type_description')
                    except Exception as e:
                        pass
                    try:
                        files[file]['size_kb'] = attrs.get('size') / 1000.0
                    except Exception as e:
                        pass
                    try:
                        files[file]['suggested_label'] = attrs.get('popular_threat_classification')\
                            .get('suggested_threat_label')
                    except Exception as e:
                        pass
                    try:
                        files[file]['observed_names'] = attrs.get('names')
                    except Exception as e:
                        pass

                    if args.comments:
                        files[file]['comments'] = list()
                        files[file]['comments'] = vt_comments(file, 'files', vt_key, sleep=sleep_time)

        files_df = pd.DataFrame.from_dict(files, orient='index').reset_index() \
            .rename(columns={'index': 'hash'}).sort_values('total', ascending=False)
        data['files'] = files_df

    with pd.ExcelWriter(outfile) as writer:
        for ioc_type, dataframe in data.items():
            dataframe.to_excel(writer, sheet_name=ioc_type, index=False)
    print(f'Results saved to {outfile}')
