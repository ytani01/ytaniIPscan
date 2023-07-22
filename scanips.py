#!/usr/bin/env python3
#
# Copyright (c) 2023 Yoichi Tanibayashi
#
"""

"""
import os
import time
import datetime
import click
import subprocess
import csv
import xmltodict
import netifaces
from my_logger import get_logger


__author__ = 'Yoichi Tanibayashi'
__date__ = '2023'


__MYNAME__ = 'scanips'
__PID__ = os.getpid()


class ScanIPsApp:
    """ ScanIPsApp

    Attributes
    ----------
    """
    __log = get_logger(__name__, False)

    XML_FILE = '/tmp/%s-%d.out' % (__MYNAME__, __PID__)
    WORK_FILE = XML_FILE + '.work'
    HTML_FILE = '/tmp/%s-%d.html' % (__MYNAME__, __PID__)

    INFO_FILE = '/home/ytani/etc/info.csv'

    PUB_INTERVAL = 10.0  # sec
    REFRESH_INTERVAL = 10.0  # sec

    MAX_AGE = 20

    def __init__(self, ip: str, dst: str = None, debug=False):
        """constructor

        Parameters
        ----------
        ip: str
            IP address e.g. '192.168.0.0/24'
        dst: str
            scp destination, e.g. host:dir/file
        """
        self._dbg = debug
        __class__.__log = get_logger(__class__.__name__, self._dbg)

        self._ip = ip
        self._dst = dst

        self._my_ipaddr = self.get_ipaddr()
        self.__log.debug('my_ipaddr=%s', self._my_ipaddr)

    def main(self):
        """ main routine
        """
        self.__log.debug('')

        host_countdown = {}

        while True:
            # load INFO_FILE
            info_list = self.load_info(self.INFO_FILE)

            # exec nmap
            self.exec_nmap(self._ip, self.XML_FILE)

            #
            # parse nmap XML
            #
            hostdata = self.parse_xml(self.XML_FILE, info_list)

            for h in hostdata:
                host_countdown[h] = self.MAX_AGE + 1

            #
            # IP list
            #
            outstr = ''
            count = 0
            human_list = []

            for h in host_countdown.keys():

                self.__log.debug('h=%s', h)

                host_countdown[h] -= 1

                if host_countdown[h] <= 0:
                    host_countdown[h] = 0
                    continue

                count += 1

                h1 = list(h)

                #
                # Human ?
                #
                if not h[4].startswith('#'):
                    name = h[4].split(' ')[0]
                    if len(name) == 0:
                        name = 'who? %d' % (count)
                        h1[4] = name + h[4]

                    human_list.append(name)

                #
                # make outstr
                #
                if len(h[2] + h[3]) > 0:
                    outstr += "%3d [%02d] %-15s %-18s %s (%s : %s)\n" % (
                        count,
                        host_countdown[h], h[0], h[1], h1[4], h[2], h[3])
                else:
                    outstr += "%3d [%02d] %-15s %-18s %s\n" % (
                        count, host_countdown[h], h[0], h[1], h1[4])

            human_list = list(set(human_list))

            self.make_html(count, human_list, outstr, self.HTML_FILE)

            #
            # send HTML file to destination
            #
            if self._dst is not None:
                subprocess.run(['scp', self.HTML_FILE, self._dst])

            self.__log.debug('count = %d, human_list = %s',
                             count, human_list)

            #
            # Sleep
            #
            time.sleep(self.PUB_INTERVAL)

        self.__log.debug('done')

    def get_ipaddr(self) -> str:
        """ get_ipaddr()
        """

        for if_name in netifaces.interfaces():

            if if_name == 'lo':
                continue

            try:
                ips = netifaces.ifaddresses(if_name)[netifaces.AF_INET]
            except KeyError:
                continue

            return ips[0]['addr']

        return ''

    def load_info(self, info_file: str) -> list:
        """ load_info

        Parameters
        ----------
        info_file: str
            Information file name (CSV)
        """

        info_list: list = []
        with open(self.INFO_FILE) as fp:
            csv_reader = csv.reader(fp)
            info_list = [row for row in csv_reader]

        self.__log.debug('info_list=%s', info_list)

        return info_list

    def exec_nmap(self, ip: str, out_file: str):
        """ exec_nmap

        Parameters
        ----------
        ip: str
            IP address e.g. '192.168.0.0/24'
        out_file: str
            output file name (XML file)
        """
        self.__log.debug('ip=%s, out_file=%s', ip, out_file)

        work_file = out_file + '.work'

        # run nmap
        cmdline = ['sudo', 'nmap', '-sP', '-oX', work_file, ip]
        out_str = subprocess.run(cmdline,
                                 capture_output=True, text=True).stdout
        self.__log.debug('out_str=\n%s', out_str)

        # mv work_file to out_file
        cmdline = ['sudo', 'mv', '-f', work_file, out_file]
        subprocess.run(cmdline)

    def parse_xml(self, xml_file: str, info_list: list):
        """ parse_xml

        Parameters
        ----------
        xml_file: str
            XML file
        info_list: list
            information data list

        Returns
        -------
        hostdata: list
           ip, mac, name, etc..
        """

        hostdata: list = []

        #
        # read XML file
        #
        try:
            with open(xml_file, encoding='utf-8') as fp:
                xml_data = fp.read()

        except Exception as e:
            self.__log.error('%s:%s', type(e).__name__, e)
            return []

        #
        # parse XML
        #
        try:
            dict_data = xmltodict.parse(xml_data)
        except Exception as e:
            self.__log.error('%s:%s', type(e).__name__, e)
            return []
        self.__log.debug('dict_data=%s', dict_data)

        if len(dict_data) <= 0:
            return []

        #
        # make host list
        #
        for d in dict_data['nmaprun']['host']:
            if type(d['address']) != list:
                continue

            ip = ''
            mac = ''
            hostname = ''
            vendor = ''
            info = ''

            for a in d['address']:
                addr = a['@addr']
                addrtype = a['@addrtype']

                if addrtype == 'ipv4':
                    ip = addr
                    continue

                if addrtype == 'mac':
                    mac = addr

                    for i in info_list:
                        if mac == i[0]:
                            info = i[1]

                if '@vendor' in a:
                    vendor = a['@vendor']

            if ip == '':
                continue

            if d['hostnames'] is not None:
                hostname = d['hostnames']['hostname']['@name']

            hostdata.append((ip, mac, hostname, vendor, info))

        return hostdata

    def make_html(self, count: int, human_list: list,
                  out_str: str, html_file: str ):
        """ make_html

        Parameters
        ----------
        count: int
        human_list: list
        out_str: str
        hotml_file: str
        """

        now_str = datetime.datetime.now().strftime('%Y-%m-%d(%a) %H:%M:%S')
        self.__log.debug('now_str=%a', now_str)

        html_str = '''<!DOCTYPE HTML>
<html>
  <head>
    <meta http-equiv="refresh" content="%d">
  </head>
  <body>
    <h3 style="text-align: left;">%s</h3>
    <blockquote>
    <h1 style="text-align: left;">up to %d peaple</h1>
    </blockquote>
    <hr />
    <pre>%s</pre>
    <hr />
    <div style="font-size: small;">%s</div>
    <div style="text-align: right; font-size: small;">by ytaniIPscan</div>
  </body>
</html>
''' % (self.REFRESH_INTERVAL, now_str, len(human_list), out_str,
       self._my_ipaddr)

        with open(html_file, mode='w') as fp:
            fp.write(html_str)

    def end(self):
        """ Call at the end of program.
        """
        self.__log.debug('')

        #
        # remove tmp files
        #
        cmdline = ['sudo', 'rm', '-fv',
                   self.XML_FILE, self.WORK_FILE, self.HTML_FILE]
        subprocess.run(cmdline)

        self.__log.debug('done')


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS, help='List IPs')
@click.argument('ip', type=str, nargs=1)
@click.option('--dst', '-s', 'dst', type=str, help='destination host:path')
@click.option('--debug', '-d', 'debug', is_flag=True, default=False,
              help='debug flag')
def main(ip, dst, debug):
    """起動用メイン関数
    """
    __log = get_logger(__name__, debug)
    __log.debug('ip=%s, dst=%s', ip, dst)

    app = ScanIPsApp(ip, dst, debug=debug)
    try:
        app.main()
    finally:
        __log.debug('finally')
        app.end()


if __name__ == '__main__':
    main()
