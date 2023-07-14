#!/usr/bin/env python3
#
# (c) 2023 Yoichi Tanibayashi
#
"""
Python3 template

### for detail and simple usage ###

$ python3 -m pydoc TemplateA.ClassA


### sample program ###

$ ./TemplateA.py -h

"""
__author__ = 'Yoichi Tanibayashi'
__date__   = '2023'

import time
import datetime
import threading
import subprocess
import xmltodict
from my_logger import get_logger


class ListIPs:
    """
    Description
    -----------

    Simple Usage
    ============
    ## Import

    from TemplateA import ClassA

    ## Initialize

    obj = ClassA()


    ## method1

    obj.method1(arg)


    ## End of program

    obj.end()

    ============

    Attributes
    ----------
    attr1: type(int|str|list of str ..)
        description
    """
    __log = get_logger(__name__, False)

    def __init__(self, opt, debug=False):
        """ Constructor

        Parameters
        ----------
        opt: type
            description
        """
        self._dbg = debug
        __class__.__log = get_logger(__class__.__name__, self._dbg)
        self.__log.debug('opt=%s', opt)

        self._opt = opt

    def end(self):
        """
        Call at the end of program
        """
        self.__log.debug('doing ..')
        print('end of %s' % __class__.__name__)
        self.__log.debug('done')

    def method1(self, arg):
        """
        Description

        Parameters
        ----------
        arg: str
            description
        """
        self.__log.debug('arg=%s', arg)

        print('%s:%s' % (arg, self._opt))

        self.__log.debug('done')


# --- 以下、サンプル ---


class ListIPsApp:
    """ ListIPsApp

    Attributes
    ----------
    """
    __log = get_logger(__name__, False)

    OUT_FILE = '/tmp/nmap.out'
    WORK_FILE = OUT_FILE + '.work'
    HTML_FILE = '/tmp/nmap.html'

    NMAP_INTERVAL = 1.0  # sec

    PUB_INTERVAL = 10.0  # sec

    MAX_AGE = 10

    def __init__(self, ip, dst, debug=False):
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

        # self._obj = ListIPs(self._opt, debug=self._dbg)

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

        while True:
            time.sleep(self.PUB_INTERVAL)

            hostdata = self.parse_xml(self.OUT_FILE)

            for h in hostdata:
                hostage[h] = self.MAX_AGE + 1

            outstr = ''
            count = 0
            for h in hostage.keys():

                hostage[h] -= 1

                if hostage[h] <= 0:
                    hostage[h] = 0
                    continue

                outstr += "%02d: %-15s %-18s %s (%s)\n" % (
                    hostage[h], h[0], h[1], h[2], h[3])

                count += 1

            outstr = "----- %s count = %d\n" % (
                datetime.datetime.now(), count) + outstr
            print(outstr)

            outstr = '<html>\n<head>\n' \
              + '<meta http-equiv="refresh" content="2; URL="\n' \
              + '</head>\n<body>\n<pre>\n' \
              + outstr \
              + '</pre>\n</body>\n</html>\n'

            with open(self.HTML_FILE, mode='w') as fp:
                fp.write(outstr)

            subprocess.run(['scp', self.HTML_FILE, self._dst])

        self.__log.debug('done')

    def parse_xml(self, xml_file):
        """ parse_xml

        Parameters
        ----------
        xml_file: str
            XML file
        """

        hostdata = []

        with open(xml_file, encoding='utf-8') as fp:
            xml_data = fp.read()

        dict_data = xmltodict.parse(xml_data)
        print(dict_data)

        for d in dict_data['nmaprun']['host']:
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
                    continue

                if addrtype == 'mac':
                    mac = addr

                if '@vendor' in a:
                    vendor = a['@vendor']

            if ip == '':
                continue

            if d['hostnames'] is not None:
                hostname = d['hostnames']['hostname']['@name']

            hostdata.append((ip, mac, vendor, hostname))

        return hostdata

    def loop_nmap(self, ip, out_file, interval):
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

    def exec_nmap(self, ip, out_file):
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


import click
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
