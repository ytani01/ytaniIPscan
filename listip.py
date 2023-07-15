#!/usr/bin/env python3
#
# Copyright (c) 2023 Yoichi Tanibayashi
#
"""

"""
import time
import datetime
import threading
import click
import subprocess
import csv
import xmltodict
from my_logger import get_logger


__author__ = 'Yoichi Tanibayashi'
__date__ = '2023'


class ListIPsApp:
    """ ListIPsApp

    Attributes
    ----------
    """
    __log = get_logger(__name__, False)

    OUT_FILE = '/tmp/listip.out'
    WORK_FILE = OUT_FILE + '.work'
    HTML_FILE = '/tmp/listip.html'
    INFO_FILE = '/home/ytani/etc/info.csv'

    NMAP_INTERVAL = 0.5  # sec
    PUB_INTERVAL = 10.0  # sec
    REFRESH_INTERVAL = 5.0  # sec

    MAX_AGE = 20

    def __init__(self, ip: str, dst: str, debug=False):
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

        self._info = []

        self._nmap_loop_active = False
        self._nmap_th = threading.Thread(target=self.loop_nmap,
                                         args=(self._ip,
                                               self.OUT_FILE,
                                               self.NMAP_INTERVAL))
        self._nmap_th.daemon = True

    def main(self):
        """ main routine
        """
        self.__log.debug('')

        self._nmap_loop_active = True
        self._nmap_th.start()

        hostage = {}

        time.sleep(self.PUB_INTERVAL)
        while True:
            time.sleep(self.PUB_INTERVAL)

            self._info = self.load_info(self.INFO_FILE)
            hostdata = self.parse_xml(self.OUT_FILE, self._info)

            for h in hostdata:
                hostage[h] = self.MAX_AGE + 1

            #
            # IP list
            #
            outstr = ''
            count = 0
            for h in hostage.keys():

                hostage[h] -= 1

                if hostage[h] <= 0:
                    hostage[h] = 0
                    continue

                count += 1

                if len(h[2] + h[3]) > 0:
                    outstr += "%3d [%02d] %-15s %-18s %s (%s:%s)\n" % (
                        count, hostage[h], h[0], h[1], h[4], h[2], h[3])
                else:
                    outstr += "%3d [%02d] %-15s %-18s %s\n" % (
                        count, hostage[h], h[0], h[1], h[4])

            now_str = datetime.datetime.now().strftime('%Y-%m-%d(%a) %H:%M:%S')
            self.__log.debug('now_str=%a', now_str)

#            outstr = "# %s, count = %d\n" % (
#                datetime.datetime.now(), count) + outstr

            #
            # HTML
            #
            html_str = '''<!DOCTYPE HTML>
<html>
  <head>
    <meta http-equiv="refresh" content="%d">
  </head>
  <body>
    <h3 style="text-align: left;">%s</h3>
    <blockquote>
    <h1 style="text-align: left;">%s</h1>
    </blockquote>
    <hr />
    <pre>%s</pre>
    <hr />
  </body>
</html>
''' % (self.REFRESH_INTERVAL, now_str, count, outstr)

            with open(self.HTML_FILE, mode='w') as fp:
                fp.write(html_str)

            subprocess.run(['scp', self.HTML_FILE, self._dst])

        self.__log.debug('done')

    def load_info(self, info_file: str):
        """ load_info

        Parameters
        ----------
        info_file: str
            Information file name (CSV)
        """

        csv_data = []
        with open(self.INFO_FILE) as fp:
            csv_reader = csv.reader(fp)
            csv_data = [row for row in csv_reader]

        self.__log.debug('csv_data=%s', csv_data)

        return csv_data

    def parse_xml(self, xml_file: str, info: list):
        """ parse_xml

        Parameters
        ----------
        xml_file: str
            XML file
        info: list
            information data list
        """

        hostdata = []

        try:
            with open(xml_file, encoding='utf-8') as fp:
                xml_data = fp.read()

        except Exception as e:
            self.__log.error('%s:%s', type(e).__name__, e)
            return {}

        try:
            dict_data = xmltodict.parse(xml_data)
        except Exception as e:
            self.__log.error('%s:%s', type(e).__name__, e)
            return {}
        self.__log.debug(dict_data)

        if len(dict_data) <= 0:
            return {}

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

                    for i in self._info:
                        if mac == i[0]:
                            info = i[1]

                if '@vendor' in a:
                    vendor = a['@vendor']

            if ip == '':
                continue

            if d['hostnames'] is not None:
                hostname = d['hostnames']['hostname']['@name']

            hostdata.append((ip, mac, vendor, hostname, info))

        return hostdata

    def loop_nmap(self, ip: str, out_file: str, interval: int):
        """ loop_nmap

        Parameters
        ----------
        ip: str
            IP address e.g. '192.168.0.0/24'
        dst: str
            scp destination, e.g. 'host:dir/file'
        interval: int
            interval sec
        """

        while self._nmap_loop_active:
            self.exec_nmap(ip, out_file)
            time.sleep(interval)

        self.__log.info('done')

    def end_nmap_loop(self):
        """ end_nmap_loop
        """
        self._nmap_loop_active = False
        self._nmap_th.join()

    def exec_nmap(self, ip: str, out_file: str):
        """ exec_nmap

        Parameters
        ----------
        ip: str
            IP address e.g. '192.168.0.0/24'
        out_file: str
            output file name
        """
        self.__log.debug('ip=%s, out_file=%s', ip, out_file)

        work_file = out_file + '.work'

        # run nmap
        cmdline = ['sudo', 'nmap', '-sP', '-oX', work_file, ip]
        subprocess.run(cmdline)

        # mv work_file to out_file
        cmdline = ['sudo', 'mv', '-f', work_file, out_file]
        subprocess.run(cmdline)

    def end(self):
        """ Call at the end of program.
        """
        self.__log.debug('doing ..')
        self.end_nmap_loop()
        # self._obj.end()
        self.__log.debug('done')


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(context_settings=CONTEXT_SETTINGS, help='''
List IPs
''')
@click.argument('ip', type=str, nargs=1)
@click.argument('dst', type=str, nargs=1)
@click.option('--debug', '-d', 'debug', is_flag=True, default=False,
              help='debug flag')
def main(ip, dst, debug):
    """起動用メイン関数
    """
    __log = get_logger(__name__, debug)
    __log.debug('ip=%s, dst=%s', ip, dst)

    app = ListIPsApp(ip, dst, debug=debug)
    try:
        app.main()
    finally:
        __log.debug('finally')
        app.end()


if __name__ == '__main__':
    main()
