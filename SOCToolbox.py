"""Repo of functions that support common use cases in SOC scripting."""
from socket import inet_aton, inet_ntoa
from struct import pack, unpack
import requests
import re
import os


def ipv4_string_to_int(ip_string):
    """Converts IPv4 address string to int for range comparison"""
    return unpack("!L", inet_aton(ip_string))[0]  # interpret bytes as unsigned long, and take single tuple value


def ipv4_int_to_string(ip_int):
    """Converts IP ints into readable string representations"""
    return inet_ntoa(pack("!L", ip_int))  # pack int as unsigned long bytes, use ntoa to convert to string val


private_a = (ipv4_string_to_int('10.0.0.0'), ipv4_string_to_int('10.255.255.255'))
private_b = (ipv4_string_to_int('172.16.0.0'), ipv4_string_to_int('172.31.255.255'))
private_c = (ipv4_string_to_int('192.168.0.0'), ipv4_string_to_int('192.168.255.255'))
apipa = (ipv4_string_to_int('169.254.0.1'), ipv4_string_to_int('169.254.255.254'))
private_ranges = [private_a, private_b, private_c, apipa]

  
def is_private(ip_string):
    """Determines if an IP falls within the standard private ranges"""
    ipv4_dec = ipv4_string_to_int(ip_string)
    for private_range in private_ranges:
        if private_range[0] <= ipv4_dec <= private_range[1]:
            return True
    return False
    

def extract_valid_iocs(file, find_hashes=False):
    """Given a text file (not unicode) that can be read normally, extract all valid IPv4 and domains"""
    with open(file, encoding='latin-1') as f:
        contents = f.read().replace('[.]', '.')  # refang IOCs and domains if defanged

    ip_pattern = re.compile(r'(?:2(?:[0-4]\d|5[0-5])|1?\d{1,2})(?:\.(?:2(?:[0-4]\d|5[0-5])|1?\d{1,2})){3}')
    domain_pattern = re.compile(r'(?:[\w\d]+\.)+[a-zA-Z]+')
    hash_pattern = re.compile(r'[A-Fa-f0-9]{32,}')  # will sometimes generate FPs on DGA subdomains
    ips = list(set(re.findall(ip_pattern, contents)))
    domains = list(set(re.findall(domain_pattern, contents)))
    if find_hashes:
        hashes = list(set(re.findall(hash_pattern, contents)))

    ioc_dict = {}
    if ips:
        ioc_dict['ip_addresses'] = ips
    if domains:
        ioc_dict['domains'] = domains
    if find_hashes and hashes:
        ioc_dict['files'] = hashes

    return ioc_dict


def file_check(file):
    """Checks if a file name string is a valid file. If not, asks for retry"""
    while not os.path.isfile(file):
        file = input("That filename didn't work, please enter another one: ")
    return file


# key below refers to the free API key we can request from freegeoip
def get_ip_geo(ipv4, key):
    res = requests.get(f'https://api.freegeoip.app/json/{ipv4}?apikey={key}').json()
    data = dict()
    data['state'] = res['region_code']
    data['city'] = res['city']
    return data


def ip_geo_buckets(ip_list, key):
    buckets = dict()
    for ip in ip_list:
        ip_geo = get_ip_geo(ip, key)
        if ip_geo['state'] in buckets:
            if ip_geo['city'] in buckets[ip_geo['state']]:
                buckets[ip_geo['state']][ip_geo['city']].append(ip)    
            else:
                buckets[ip_geo['state']][ip_geo['city']] = [ip]
        else:
            buckets[ip_geo['state']] = {ip_geo['city']: ip}
    return buckets
