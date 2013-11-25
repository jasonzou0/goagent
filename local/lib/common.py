__version__ = '3.0.9a'

import collections
import ConfigParser
import fnmatch
import os
import random
import sys
import re

try:
    import gevent
except ImportError:
    gevent = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None


class Common(object):
    """Global Config Object"""

    basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def __init__(self, config_file='proxy.ini', use_dev_appserver=False):
        self._use_dev_appserver = use_dev_appserver

        """load config from proxy.ini"""
        ConfigParser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = ConfigParser.ConfigParser()
        self.CONFIG_FILENAME = os.path.join(Common.basedir, config_file)
        self.CONFIG.read(self.CONFIG_FILENAME)

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')
        self.LISTEN_VISIBLE = self.CONFIG.getint('listen', 'visible')
        self.LISTEN_DEBUGINFO = self.CONFIG.getint('listen', 'debuginfo') if self.CONFIG.has_option('listen', 'debuginfo') else 0

        self.GAE_APPIDS = re.findall(r'[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile')
        self.GAE_MODE = self.CONFIG.get('gae', 'mode')
        self.GAE_HOSTS = self.CONFIG.get('gae', 'hosts')
        self.GAE_WINDOW = self.CONFIG.getint('gae', 'window') if self.CONFIG.has_option('gae', 'window') else self.CONFIG.getint(self.GAE_PROFILE, 'window')
        self.GAE_CRLF = self.CONFIG.getint('gae', 'crlf')
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')
        self.GAE_OBFUSCATE = self.CONFIG.getint('gae', 'obfuscate') if self.CONFIG.has_option('gae', 'obfuscate') else 0
        self.GAE_OPTIONS = self.CONFIG.get('gae', 'options') if self.CONFIG.has_option('gae', 'options') else ''
        m = re.match(r'\[(\w+)\](\w+)', self.GAE_HOSTS)
        if m:
            self.GAE_HOSTS = self.CONFIG.get(m.group(1), m.group(2)).split('|')
        else:
            self.GAE_HOSTS = (self.GAE_HOSTS or self.CONFIG.get(self.GAE_PROFILE, 'hosts')).split('|')

        self.PAC_ENABLE = self.CONFIG.getint('pac', 'enable')
        self.PAC_IP = self.CONFIG.get('pac', 'ip')
        self.PAC_PORT = self.CONFIG.getint('pac', 'port')
        self.PAC_FILE = self.CONFIG.get('pac', 'file').lstrip('/')
        self.PAC_GFWLIST = self.CONFIG.get('pac', 'gfwlist')
        self.PAC_ADBLOCK = self.CONFIG.get('pac', 'adblock') if self.CONFIG.has_option('pac', 'adblock') else ''
        self.PAC_EXPIRED = self.CONFIG.getint('pac', 'expired')

        self.PAAS_ENABLE = self.CONFIG.getint('paas', 'enable')
        self.PAAS_LISTEN = self.CONFIG.get('paas', 'listen')
        self.PAAS_PASSWORD = self.CONFIG.get('paas', 'password') if self.CONFIG.has_option('paas', 'password') else ''
        self.PAAS_CRLF = self.CONFIG.getint('paas', 'crlf') if self.CONFIG.has_option('paas', 'crlf') else 1
        self.PAAS_VALIDATE = self.CONFIG.getint('paas', 'validate') if self.CONFIG.has_option('paas', 'validate') else 0
        self.PAAS_FETCHSERVER = self.CONFIG.get('paas', 'fetchserver')

        self.PROXY_ENABLE = self.CONFIG.getint('proxy', 'enable')
        self.PROXY_AUTODETECT = self.CONFIG.getint('proxy', 'autodetect') if self.CONFIG.has_option('proxy', 'autodetect') else 0
        self.PROXY_HOST = self.CONFIG.get('proxy', 'host')
        self.PROXY_PORT = self.CONFIG.getint('proxy', 'port')
        self.PROXY_USERNAME = self.CONFIG.get('proxy', 'username')
        self.PROXY_PASSWROD = self.CONFIG.get('proxy', 'password')

        if not self.PROXY_ENABLE and self.PROXY_AUTODETECT:
            from proxy_util import ProxyUtil
            system_proxy = ProxyUtil.get_system_proxy()
            if system_proxy and self.LISTEN_IP not in system_proxy:
                _, username, password, address = ProxyUtil.parse_proxy(system_proxy)
                proxyhost, _, proxyport = address.rpartition(':')
                self.PROXY_ENABLE = 1
                self.PROXY_USERNAME = username
                self.PROXY_PASSWROD = password
                self.PROXY_HOST = proxyhost
                self.PROXY_PORT = int(proxyport)
        if self.PROXY_ENABLE:
            self.GAE_MODE = 'https'
            self.proxy = 'https://%s:%s@%s:%d' % (self.PROXY_USERNAME or '', self.PROXY_PASSWROD or '', self.PROXY_HOST, self.PROXY_PORT)
        else:
            self.proxy = ''

        self.GOOGLE_WINDOW = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
        self.GOOGLE_HOSTS = [x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x]
        self.GOOGLE_SITES = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)
        self.GOOGLE_FORCEHTTPS = tuple('http://'+x for x in self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|') if x)
        self.GOOGLE_WITHGAE = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|') if x)

        self.AUTORANGE_HOSTS = self.CONFIG.get('autorange', 'hosts').split('|')
        self.AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in self.AUTORANGE_HOSTS]
        self.AUTORANGE_ENDSWITH = tuple(self.CONFIG.get('autorange', 'endswith').split('|'))
        self.AUTORANGE_NOENDSWITH = tuple(self.CONFIG.get('autorange', 'noendswith').split('|'))
        self.AUTORANGE_MAXSIZE = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE = self.CONFIG.getint('autorange', 'bufsize')
        self.AUTORANGE_THREADS = self.CONFIG.getint('autorange', 'threads')

        self.FETCHMAX_LOCAL = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
        self.FETCHMAX_SERVER = self.CONFIG.get('fetchmax', 'server')

        if self.CONFIG.has_section('dns'):
            self.DNS_ENABLE = self.CONFIG.getint('dns', 'enable')
            self.DNS_LISTEN = self.CONFIG.get('dns', 'listen')
            self.DNS_REMOTE = self.CONFIG.get('dns', 'remote')
            self.DNS_TIMEOUT = self.CONFIG.getint('dns', 'timeout')
            self.DNS_CACHESIZE = self.CONFIG.getint('dns', 'cachesize')
        else:
            self.DNS_ENABLE = 0

        if self.CONFIG.has_section('light'):
            self.LIGHT_ENABLE = self.CONFIG.getint('light', 'enable')
            self.LIGHT_PASSWORD = self.CONFIG.get('light', 'password')
            self.LIGHT_LISTEN = self.CONFIG.get('light', 'listen')
            self.LIGHT_SERVER = self.CONFIG.get('light', 'server')
        else:
            self.LIGHT_ENABLE = 0

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

        self.LOVE_ENABLE = self.CONFIG.getint('love', 'enable')
        self.LOVE_TIP = self.CONFIG.get('love', 'tip').encode('utf8').decode('unicode-escape').split('|')

        DictType = getattr(collections, 'OrderedDict', dict)
        self.HOSTS = DictType(self.CONFIG.items('hosts'))
        for key, value in self.HOSTS.items():
            m = re.match(r'\[(\w+)\](\w+)', value)
            if m:
                self.HOSTS[key] = self.CONFIG.get(m.group(1), m.group(2))
        self.HOSTS_MATCH = DictType((re.compile(k).search, v) for k, v in self.HOSTS.items() if not re.search(r'\d+$', k))
        self.HOSTS_CONNECT_MATCH = DictType((re.compile(k).search, v) for k, v in self.HOSTS.items() if re.search(r'\d+$', k))

        random.shuffle(self.GAE_APPIDS)
        # Sets self.GAE_FETCHSERVER
        self.reset_gae_fetchserver()


    def reset_gae_fetchserver(self):
        base_address = ''
        if self._use_dev_appserver:
            base_address = 'http://localhost:8080'
        else:
            base_address = '%s://%s.appspot.com' % (self.GAE_MODE, self.GAE_APPIDS[0])
        self.GAE_FETCHSERVER = '%s%s?' % (base_address, self.GAE_PATH)


    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version[:5], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Uvent Version      : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Local Proxy        : %s:%s\n' % (self.PROXY_HOST, self.PROXY_PORT) if self.PROXY_ENABLE else ''
        info += 'Debug INFO         : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'GAE Mode           : %s\n' % self.GAE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        info += 'GAE Validate       : %s\n' % self.GAE_VALIDATE if self.GAE_VALIDATE else ''
        info += 'GAE Obfuscate      : %s\n' % self.GAE_OBFUSCATE if self.GAE_OBFUSCATE else ''
        if common.PAC_ENABLE:
            info += 'Pac Server         : http://%s:%d/%s\n' % (self.PAC_IP, self.PAC_PORT, self.PAC_FILE)
            info += 'Pac File           : file://%s\n' % os.path.join(Common.basedir, self.PAC_FILE).replace('\\', '/')
        if common.PAAS_ENABLE:
            info += 'PAAS Listen        : %s\n' % common.PAAS_LISTEN
            info += 'PAAS FetchServer   : %s\n' % common.PAAS_FETCHSERVER
        if common.DNS_ENABLE:
            info += 'DNS Listen         : %s\n' % common.DNS_LISTEN
            info += 'DNS Remote         : %s\n' % common.DNS_REMOTE
        if common.LIGHT_ENABLE:
            info += 'LIGHT Listen       : %s\n' % common.LIGHT_LISTEN
            info += 'LIGHT Server       : %s\n' % common.LIGHT_SERVER
        info += '------------------------------------------------------\n'
        return info


def use_dev_gae_fetch_server():
    """Parse cmdline flags to check if user wants to use dev GAE fetch server."""
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--use_dev_gae_fetch_server', help='Use dev GAE fetch server', 
                        nargs='?', type=bool, default=False)
    return True if parser.parse_args().use_dev_gae_fetch_server else False


common = Common(use_dev_appserver = use_dev_gae_fetch_server(),
                config_file='myproxy.ini')
