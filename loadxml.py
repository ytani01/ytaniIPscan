#!/usr/bin/env python3
#
# Copywrite (c) 2023 Yoichi Tanibayahshi
#
import xmltodict
import json

xmlfile = '/tmp/nmap-loop.sh.out'

with open(xmlfile, encoding='utf-8') as fp_xml:
    data_xml = fp_xml.read()

data_dict = xmltodict.parse(data_xml)

for d in data_dict['nmaprun']['host']:
    if type(d['address']) != list:
        continue

    ip = ''
    mac = ''
    hostname = ''
    vendor = ''
    
    for a in d['address']:
        addr = a['@addr']
        addrtype = a['@addrtype']

        if addrtype == 'ipv4':
            ip = addr

        if addrtype == 'mac':
            mac = addr

        if '@vendor' in a:
            vendor = a['@vendor']

    if d['hostnames'] is not None:
        hostname = d['hostnames']['hostname']['@name']

    print('%-15s %s %s (%s)' % (ip, mac, vendor, hostname))
