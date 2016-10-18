# -*- coding: utf8 -*-

import socket
import requests
from threading import Thread, Lock


class CheckTask(Thread):
    """
    Handle single task of iptables.
    """

    def __init__(self, tag, cfg, ipStatus, glock):
        """
        :param tag(str): project name
        :param cfg(dict): cfg in json format
        :param ipStatus(dict): dict stores ip status
        :param glock(*threading.Lock): threading global lock
        """
        super(CheckTask, self).__init__()
        self.tag = tag
        self.cfg = cfg
        self.ipStatus = ipStatus
        self.glock = glock
        self.downIps = set()
        self.lock = Lock()

    def _check_port(self, ip, port, maxRetries, timeout):
        retries = 0
        while retries < maxRetries:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ret = sock.connect_ex((ip, port))
            sock.close()
            if ret != 0:
                retries += 1
                if retries == maxRetries:
                    with self.lock:
                        self.downIps.add(ip)
                    return
                continue
            return

    def _check_url(self, ip, url, headers, maxRetries, timeout):
        endpoint = url.format(dstip=ip)
        retries = 0
        while retries < maxRetries:
            try:
                req = requests.head(endpoint, headers=headers, timeout=timeout)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.ReadTimeout):
                retries += 1
                if retries == maxRetries:
                    with self.lock:
                        self.downIps.add(ip)
                continue
            req.close()
            if req.status_code >= 400:
                with self.lock:
                    self.downIps.add(ip)
            return

    def _check_service(self):
        checkArgs = {
            'maxRetries': 3,
            'timeout': 1.0
        }
        checkCfg = self.cfg.get('check')
        target, args = None, None
        if checkCfg is None:
            # the first rule dport is ready to check
            # if no specified url or port is provided
            firstRule = self.cfg['prerouting']['rules'][0]
            checkArgs['dport'] = int(firstRule['dport'])
            target = self._check_port
            args = [
                None,
                checkArgs['dport'],
                checkArgs['maxRetries'],
                checkArgs['timeout']
            ]
        else:
            checkArgs['maxRetries'] = checkCfg.get(
                                'retries', checkArgs['maxRetries'])
            checkArgs['timeout'] = checkCfg.get(
                                'timeout', checkArgs['timeout'])
            checkArgs['headers'] = checkCfg.get(
                                'headers', {"Host": "api-m-hs.xd.com"})
            if len(checkCfg.get('url', '')) > 0:
                checkArgs['url'] = checkCfg['url']
                target = self._check_url
                args = [
                    None,
                    checkArgs['url'],
                    checkArgs['headers'],
                    checkArgs['maxRetries'],
                    checkArgs['timeout']
                ]
            else:
                firstRule = self.cfg['prerouting']['rules'][0]
                checkArgs['dport'] = int(firstRule['dport'])
                target = self._check_port
                args = [
                    None,
                    checkArgs['dport'],
                    checkArgs['maxRetries'],
                    checkArgs['timeout']
                ]
        # run in multithread mode
        threads = []
        for mode in self.cfg['dstip']:
            # replace args[0] with specified dstip
            args[0] = self.cfg['dstip'][mode]
            t = Thread(target=target, args=tuple(args))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    def run(self):
        # 0: ok
        # 1: secdonary fail
        # 2: primary fail
        # 3: both fail
        self._check_service()
        with self.glock:
            if len(self.downIps) == 0:
                self.ipStatus[self.tag] = 0
            elif len(self.downIps) == 1:
                if self.cfg['dstip']['secondary'] in self.downIps:
                    self.ipStatus[self.tag] = 1
                else:
                    self.ipStatus[self.tag] = 2
            else:
                self.ipStatus[self.tag] = 3
