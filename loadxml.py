#!/usr/bin/env python3
#
# Copywrite (c) 2023 Yoichi Tanibayahshi
#
import xmltodict
import time
import datetime


INTERVAL_SEC = 10 # sec
MAX_AGE = 10

xmlfile = '/tmp/nmap-loop.sh.out'


def load_hostdata(xmlfile:str):
    hostdata = []

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

        if ip == '':
            continue

        if d['hostnames'] is not None:
            hostname = d['hostnames']['hostname']['@name']

        hostdata.append((ip, mac, vendor, hostname))

        # print('%-15s %s %s (%s)' % (ip, mac, vendor, hostname))

    return hostdata


hostage = {}
while True:
    print("----- %s" % (datetime.datetime.now()))

    hostdata = load_hostdata(xmlfile)

    for h in hostdata:
        hostage[h] = MAX_AGE + 1

    count = 0
    for h in hostage.keys():

        hostage[h] -= 1

        if hostage[h] <= 0:
            hostage[h] = 0
            continue

        print("%02d: %-15s %-18s %s (%s)" % (hostage[h],
                                        h[0], h[1], h[2], h[3]))
        count += 1

    print("----- %s,  count = %d" %
          (datetime.datetime.now(), count))

    time.sleep(INTERVAL_SEC)
