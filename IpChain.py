# -*- coding: utf8 -*-

import iptc


class NATChain(object):

    table = iptc.Table(iptc.Table.NAT)
    """
    Iptables NAT chain.
    """

    def __init__(self, name):
        """
        :param name(str): chain name
        """
        self.chain = iptc.Chain(self.table, name)

    @classmethod
    def is_chain(cls, name):
        """
        :param name(str): chain name
        """
        cls.table.refresh()
        return cls.table.is_chain(name)

    @classmethod
    def create_chain(cls, name):
        """
        :param name(str): chain name
        """
        cls.table.create_chain(name)

    def fetch_all_targets(self):
        self.table.refresh()
        targets = []
        for rule in self.chain.rules:
            targets.append(rule.target.name)
        return targets

    def fetch_dst_ip(self):
        self.table.refresh()
        if len(self.chain.rules) > 0:
            target_parameters = self.chain.rules[0].target.get_all_parameters()
            to_destination = target_parameters.get('to-destination')
            if to_destination is not None:
                return to_destination[0].split(':')[0]
        return None

    def append_pre_rule(self, proto, dport, target, to_destination):
        """
        :param proto(str): rule protocol
        :param dport(str): rule dport
        :param target(str): rule target
        :param to_destination(str): rule to_destination
        """
        rule = iptc.Rule()
        rule.protocol = proto
        if dport is not None:
            match = rule.create_match(proto)
            match.dport = dport
        target = rule.create_target(target)
        if to_destination is not None:
            target.to_destination = to_destination
        self.chain.append_rule(rule)

    def append_post_rule(self, proto, dst, target):
        """
        :param proto(str): rule protocol
        :param dst(str): rule dst
        :param target(str): rule target
        """
        rule = iptc.Rule()
        rule.protocol = proto
        if dst is not None:
            rule.dst = dst
        target = rule.create_target(target)
        self.chain.append_rule(rule)

    def flush(self):
        self.chain.flush()


if __name__ == '__main__':
    pass
