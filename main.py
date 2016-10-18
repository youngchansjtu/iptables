#!/usr/bin/env python2
# -*- coding: utf8 -*-

import time
import threading
import socket
import argparse
from IpChain import NATChain
from IpCheck import CheckTask
from utils import to_date, to_str, to_unicode, send_pushover, read_cfg


def create_user_chains(cfg):
    targets = {}
    preroutingChain = NATChain('PREROUTING')
    postroutingChain = NATChain('POSTROUTING')
    targets['prerouting'] = preroutingChain.fetch_all_targets()
    targets['postrouting'] = postroutingChain.fetch_all_targets()

    for tag in cfg:
        preUserChainName = cfg[tag]['prerouting']['chain']
        postUserChainName = cfg[tag]['postrouting']['chain']

        if not NATChain.is_chain(preUserChainName):
            NATChain.create_chain(preUserChainName)
        if not NATChain.is_chain(postUserChainName):
            NATChain.create_chain(postUserChainName)

        if not preUserChainName in targets['prerouting']:
            preroutingChain.append_pre_rule('ip', None, preUserChainName, None)
        if not postUserChainName in targets['postrouting']:
            postroutingChain.append_post_rule('ip', None, postUserChainName)


def fetch_ip_status(cfg, tags=None):
    # 0: ok; 1: secondary fail; 2: primary fail; 3: both fail
    if tags is None:
        tags = cfg.keys()
    ipStatus = {}
    glock = threading.Lock()
    threads = []
    for tag in tags:
        t = CheckTask(tag, cfg[tag], ipStatus, glock)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return ipStatus


def reload_cfg(cfg, tags):
    """
    :param cfg(dict): json data
    :param tags(list): tag list 
    """
    ipStatus = fetch_ip_status(cfg, tags)
    create_user_chains(cfg)
    for tag in tags:
        preUserChainName = cfg[tag]['prerouting']['chain']
        postUserChainName = cfg[tag]['postrouting']['chain']
        # check if user-defined chains exist
        if not NATChain.is_chain(preUserChainName):
            NATChain.create_chain(preUserChainName)
        if not NATChain.is_chain(postUserChainName):
            NATChain.create_chain(postUserChainName)

        preUserChain = NATChain(preUserChainName)
        postUserChain = NATChain(postUserChainName)
        primaryIp = cfg[tag]['dstip']['primary']
        secondaryIp = cfg[tag]['dstip']['secondary']

        dstip = preUserChain.fetch_dst_ip()
        if dstip is None:
            if ipStatus[tag] == 0:
                dstip = primaryIp
            elif ipStatus[tag] == 1:
                dstip = primaryIp
            elif ipStatus[tag] == 2:
                dstip = secondaryIp
            else:
                print('{tag}: no available dstip to apply'.format(tag=to_str(tag)))
                continue
        # reload iptables rules
        preUserChain.flush()
        for rule in cfg[tag]['prerouting']['rules']:
            to_destination = ':'.join((dstip, rule['to_ports']))
            preUserChain.append_pre_rule(rule['proto'], rule['dport'], rule['target'], to_destination)
        postUserChain.flush()
        for rule in cfg[tag]['postrouting']['rules']:
            postUserChain.append_post_rule(rule['proto'], dstip, rule['target'])
        print('{tag}: succeed to reload rules'.format(tag=to_str(tag)))


def do_failover(cfg, tags):
    """
    :param cfg(dict): json data
    :param tags(list): tag list
    """
    create_user_chains(cfg)
    for tag in tags:
        preUserChainName = cfg[tag]['prerouting']['chain']
        postUserChainName = cfg[tag]['postrouting']['chain']
        preUserChain = NATChain(preUserChainName)
        postUserChain = NATChain(postUserChainName)
        primaryIp = cfg[tag]['dstip']['primary']
        secondaryIp = cfg[tag]['dstip']['secondary']

        foip = None # failover dstip
        dstip = preUserChain.fetch_dst_ip()
        # we won't check failover ip is available or not
        # just do failover if rules are found
        if dstip is None:
            print('{tag}: chain is empty, apply rules first.'.format(tag=to_str(tag)))
            continue
        elif dstip == primaryIp:
            foip = secondaryIp
        elif dstip == secondaryIp:
            foip = primaryIp

        if foip is not None:
            # reload iptables rules
            preUserChain.flush()
            for rule in cfg[tag]['prerouting']['rules']:
                to_destination = ':'.join((foip, rule['to_ports']))
                preUserChain.append_pre_rule(rule['proto'], rule['dport'], rule['target'], to_destination)
            postUserChain.flush()
            for rule in cfg[tag]['postrouting']['rules']:
                postUserChain.append_post_rule(rule['proto'], foip, rule['target'])
            print('{tag}: succeed to failover'.format(tag=to_str(tag)))


def start_scheduler(cfg, seconds):
    # lastDownTime: `None` means nothing happened last check
    lastDownTime = {}
    pushover = {}

    while True:
        # Stage 1: create new user-defined chains
        create_user_chains(cfg)

        # Stage 2: start ip check task
        ipStatus = fetch_ip_status(cfg)

        # Stage 3: check iptables rule
        for tag in cfg:
            preUserChainName = cfg[tag]['prerouting']['chain']
            postUserChainName = cfg[tag]['postrouting']['chain']
            preUserChain = NATChain(preUserChainName)
            postUserChain = NATChain(postUserChainName)

            primaryIp = cfg[tag]['dstip']['primary']
            secondaryIp = cfg[tag]['dstip']['secondary']
            dstip = preUserChain.fetch_dst_ip()
            timeNow = int(time.time())
            # 0: ok; 1: secondary fail; 2: primary fail; 3: both fail
            lastDownTime.setdefault(tag, {'time': None, 'status': 0})
            pushover.setdefault(tag, {'message': None, 'priority': 0})

            if dstip is None:
            # load cfg at the first time
                if ipStatus[tag] == 0:
                    dstip = primaryIp
                    pushover[tag]['message'] = u'可用主线IP：{ip1}\n可用备线IP：{ip2}\n业务受影响评估：无\n'.format(
                                                                                                ip1=primaryIp,
                                                                                                ip2=secondaryIp)
                elif ipStatus[tag] == 1:
                    dstip = primaryIp
                    lastDownTime[tag] = {
                        'time': timeNow,
                        'status': 1
                    }
                    pushover[tag]['message'] = u'可用主线IP：{ip1}\n故障备线IP：{ip2}\n业务受影响评估：中\n'.format(
                                                                                                ip1=primaryIp,
                                                                                                ip2=secondaryIp)
                elif ipStatus[tag] == 2:
                    dstip = secondaryIp
                    lastDownTime[tag] = {
                        'time': timeNow,
                        'status': 2
                    }
                    pushover[tag]['message'] = u'故障主线IP：{ip1}\n可用备线IP：{ip2}\n业务受影响评估：中\n'.format(
                                                                                                ip1=primaryIp,
                                                                                                ip2=secondaryIp)
                elif ipStatus[tag] == 3:
                    lastDownTime[tag] = {
                        'time': timeNow,
                        'status': 3
                    }
                    pushover[tag]['message'] = u'故障主线IP：{ip1}\n故障备线IP：{ip2}\n业务受影响评估：高\n'.format(
                                                                                                ip1=primaryIp,
                                                                                                ip2=secondaryIp)
                    pushover[tag]['priority'] = 1
                # apply iptables rules in preUserChain and postUserChain if not both failed
                if dstip is not None:
                    for rule in cfg[tag]['prerouting']['rules']:
                        to_destination = ':'.join((dstip, rule['to_ports']))
                        preUserChain.append_pre_rule(rule['proto'], rule['dport'], rule['target'], to_destination)
                    for rule in cfg[tag]['postrouting']['rules']:
                        postUserChain.append_post_rule(rule['proto'], dstip, rule['target'])
                    if ipStatus[tag] < 3:
                        _dstip = preUserChain.fetch_dst_ip()
                        pushover[tag]['message'] += u'已生效IP：{ip}\n'.format(ip=_dstip)
            else:
                if ipStatus[tag] == 0:
                    if lastDownTime[tag]['status'] != 0:
                        # send pushover at once if both failed and recover
                        if lastDownTime[tag]['status'] == 3:
                            pushover[tag]['message'] = u'事件：主/备线路IP已恢复可用\n业务受影响评估：无\n'
                            lastDownTime[tag] = {
                                'time': None,
                                'status': 0
                            }
                        else:
                            # send pushover when no downtime in the recent 10 minutes if not both failed and recover
                            if timeNow - lastDownTime[tag]['time'] >= 600:
                                if lastDownTime[tag]['status'] == 1:
                                    pushover[tag]['message'] = u'事件：备线路IP已恢复可用\n业务受影响评估：无\n'
                                elif lastDownTime['tag']['status'] == 2:
                                    pushover[tag]['message'] = u'事件：主线路IP已恢复可用\n业务受影响评估：无\n'
                                lastDownTime[tag] = {
                                    'time': None,
                                    'status': 0
                                }
                elif ipStatus[tag] == 1:
                    if dstip == primaryIp:
                        # dstip equals to primaryIp
                        # nothing to do but send pushover 
                        message = u'可用主线IP：{ip1}\n故障备线IP：{ip2}\n业务受影响评估：中\n已生效IP：{ip3}\n'.format(
                                                                                                    ip1=primaryIp,
                                                                                                    ip2=secondaryIp,
                                                                                                    ip3=dstip)
                        if lastDownTime[tag]['status'] != 1:
                            lastDownTime[tag] = {
                                'time': timeNow,
                                'status': 1
                            }
                            pushover[tag]['message'] = message
                        else:
                            # send pushover every 5 minutes
                            if timeNow - lastDownTime[tag]['time'] >= 300:
                                lastDownTime[tag]['time'] = timeNow
                                pushover[tag]['message'] = message
                    else:
                        lastDownTime[tag] = {
                            'time': timeNow,
                            'status': 1
                        }
                        message = u'可用主线IP：{ip1}\n故障备线IP：{ip2}\n业务受影响评估：中\n'.format(
                                                                                    ip1=primaryIp,
                                                                                    ip2=secondaryIp)
                        dstip = primaryIp
                        # apply iptables rules in preUserChain and postUserChain
                        preUserChain.flush()
                        for rule in cfg[tag]['prerouting']['rules']:
                            to_destination = ':'.join((dstip, rule['to_ports']))
                            preUserChain.append_pre_rule(rule['proto'], rule['dport'], rule['target'], to_destination)
                        postUserChain.flush()
                        for rule in cfg[tag]['postrouting']['rules']:
                            postUserChain.append_post_rule(rule['proto'], dstip, rule['target'])
                        # fetch new dstip after apply rules
                        _dstip = preUserChain.fetch_dst_ip()
                        pushover[tag]['message'] = message + u'已生效IP：{ip}\n'.format(ip=_dstip)
                elif ipStatus[tag] == 2:
                    if dstip == secondaryIp:
                        # dstip equals to secondaryIp
                        # nothing to do but send pushover
                        message = u'故障主线IP：{ip1}\n可用备线IP：{ip2}\n业务受影响程度：中\n已生效IP: {ip3}\n'.format(
                                                                                                    ip1=primaryIp,
                                                                                                    ip2=secondaryIp,
                                                                                                    ip3=dstip)
                        if lastDownTime[tag]['status'] != 2:
                            lastDownTime[tag] = {
                                'time': timeNow,
                                'status': 2
                            }
                            pushover[tag]['message'] = message
                        else:
                            # send pushover every 5 minutes
                            if timeNow - lastDownTime[tag]['time'] >= 300:
                                lastDownTime[tag]['time'] = timeNow
                                pushover[tag]['message'] = message
                    else:
                        lastDownTime[tag] = {
                            'time': timeNow,
                            'status': 2
                        }
                        message = u'故障主线IP：{ip1}\n可用备线IP：{ip2}\n业务受影响评估：中\n'.format(
                                                                                    ip1=primaryIp,
                                                                                    ip2=secondaryIp)
                        dstip = secondaryIp
                        # apply iptables rules in preUserChain and postUserChain
                        preUserChain.flush()
                        for rule in cfg[tag]['prerouting']['rules']:
                            to_destination = ':'.join((dstip, rule['to_ports']))
                            preUserChain.append_pre_rule(rule['proto'], rule['dport'], rule['target'], to_destination)
                        postUserChain.flush()
                        for rule in cfg[tag]['postrouting']['rules']:
                            postUserChain.append_post_rule(rule['proto'], dstip, rule['target'])
                        # fetch new dstip after apply rules
                        _dstip = preUserChain.fetch_dst_ip()
                        pushover[tag]['message'] = message + u'已生效IP：{ip}\n'.format(ip=_dstip)
                elif ipStatus[tag] == 3:
                    # send pushover every minute when both failed
                    message = u'故障主线IP：{ip1}\n故障备线IP：{ip2}\n业务受影响评估：高\n'.format(
                                                                                ip1=primaryIp,
                                                                                ip2=secondaryIp)
                    if lastDownTime[tag]['status'] != 3:
                        lastDownTime[tag] = {
                            'time': timeNow,
                            'status': 3
                        }
                        pushover[tag]['message'] = message
                        pushover[tag]['priority'] = 1
                    else:
                        # send pushover every minute
                        if timeNow - lastDownTime[tag]['time'] >= 60:
                            lastDownTime[tag]['time'] = timeNow
                            pushover[tag]['message'] = message
                            pushover[tag]['priority'] = 1


        # Stage 4: Send pushover
        for tag in pushover:
            if pushover[tag]['message'] is not None:
                timestamp = lastDownTime[tag]['time'] \
                            if lastDownTime[tag]['time'] is not None \
                            else timeNow
                message = u'项目：{tag}\n时间：{timestamp}\nECS实例：{hostname}\n'.format(
                                                            tag=tag,
                                                            timestamp=to_date(timestamp),
                                                            hostname=socket.gethostname())
                message += pushover[tag]['message']
                ret = send_pushover(to_str(message), pushover[tag]['priority'])
                if ret == 200:
                    pushover[tag] = {
                        'message': None,
                        'priority': 0
                    }
        time.sleep(seconds)


def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    parser.add_argument('--config', metavar='FILENAME', type=str, default='cfg.json',
                                            help='cfg file name (defaults to cfg.json)')
    group.add_argument('--reload', metavar='NAME', dest='reloads', action='append',
                                            help='reload iptables rules from cfg')
    group.add_argument('--failover', metavar='NAME', dest='failovers', action='append',
                                            help='failover dstip')
    group.add_argument('--scheduler', metavar='SECONDS', dest='seconds', type=float, default=5,
                                            help='run in scheduler mode every N seconds (defaults to 5)')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    cfg = read_cfg(args.config)
    if args.reloads is not None:
        if 'all' in args.reloads:
            tags = cfg.keys()
        else:
            tags = args.reloads
        tags = tuple((to_unicode(tag) for tag in tags if to_unicode(tag) in cfg))
        reload_cfg(cfg, tags)
    elif args.failovers is not None:
        if 'all' in args.failovers:
            tags = cfg.keys()
        else:
            tags = args.failovers
        tags = tuple((to_unicode(tag) for tag in tags if to_unicode(tag) in cfg))
        do_failover(cfg, tags)
    else:
        start_scheduler(cfg, args.seconds)


if __name__ == '__main__':
    main()
