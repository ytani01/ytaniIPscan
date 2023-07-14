#!/usr/bin/env python3
#
# Copywrite (c) 2023 Yoichi Tanibayahshi
#
import sys
import subprocess
import xmltodict
import time
import datetime

DEF_DST = 'ssh.ytani.net:public_html'
INTERVAL_SEC = 10 # sec
MAX_AGE = 10

print(sys.argv)
if len(sys.argv) <= 1:
    print('usage: %s xml_file' % (sys.argv[0]))
    sys.exit(1)

xmlfile = sys.argv[1]

outfile = None
if len(sys.argv) >= 3:
    outfile = sys.argv[2]
print(outfile)

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
    hostdata = load_hostdata(xmlfile)

    for h in hostdata:
        hostage[h] = MAX_AGE + 1

    outstr = ''
    count = 0
    for h in hostage.keys():

        hostage[h] -= 1

        if hostage[h] <= 0:
            hostage[h] = 0
            continue

        outstr += "%02d: %-15s %-18s %s (%s)\n" % (hostage[h], h[0], h[1], h[2], h[3])

        count += 1

    outstr = "----- %s count = %d\n" % (datetime.datetime.now(), count) + outstr
    print(outstr)

    if outfile is not None:
        outstr = '<html>\n<head>\n' \
        + '<meta http-equiv="refresh" content="2; URL="\n' \
        + '</head>\n<body>\n<pre>\n' \
        + outstr \
        + '</pre>\n</body>\n</html>\n'

        with open(outfile, mode='w') as fp_out:
            fp_out.write(outstr)

        subprocess.run(['scp', outfile, DEF_DST])

    time.sleep(INTERVAL_SEC)
