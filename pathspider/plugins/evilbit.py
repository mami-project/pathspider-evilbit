from scapy.all import IP  # pylint: disable=no-name-in-module
from scapy.all import IPv6  # pylint: disable=no-name-in-module
from scapy.all import UDP  # pylint: disable=no-name-in-module
from scapy.all import TCP  # pylint: disable=no-name-in-module
from scapy.all import DNS  # pylint: disable=no-name-in-module
from scapy.all import DNSQR  # pylint: disable=no-name-in-module
from scapy.all import RandShort  # pylint: disable=no-name-in-module

import pathspider
from pathspider.base import PluggableSpider
from pathspider.forge import ForgeSpider
from pathspider.chains.dns import DNSChain
from pathspider.chains.basic import BasicChain
from pathspider.chains.tcp import TCPChain
from pathspider.chains.evil import EvilChain
from pathspider.chains.base import Chain
from pathspider.chains.tcp import TCP_SYN, TCP_SA

class EvilBit(ForgeSpider, PluggableSpider):

    name = "evilbit"
    description = "Evil bit connectivity testing"
    version = '0.0.0'
    chains = [BasicChain, DNSChain, TCPChain, EvilChain]
    connect_supported = ["tcpsyn", "dnsudp"]
    packets = 2

    def forge(self, job, seq):
        sport = 0
        while sport < 1024:
            sport = int(RandShort())
        if self.args.connect == 'tcpsyn':
            l4 = (TCP(sport=sport, dport=job['dp']))
        if self.args.connect == 'dnsudp':
            l4 = (UDP(sport=sport, dport=job['dp']) /
                  DNS(qd=DNSQR(qname=job['domain'])))
        if ':' in job['dip']:
            ip = IPv6(src=self.source[1], dst=job['dip'])
        else:
            ip = IP(src=self.source[0], dst=job['dip'])
        if seq == 1:
            #### TODO: Set the 'evil' flag if it's the second packet
        return ip/l4
    

    def combine_flows(self, flows):
        for flow in flows:
            if not flow['observed']:
                return ['pathspider.not_observed']

        conditions = []
        conn0 = False
        conn1 = False

        if self.args.connect == 'tcpsyn':
            if flows[0]['tcp_synflags_rev'] is not None and flows[0][
                    'tcp_synflags_rev'] & TCP_SA == TCP_SA:
                conn0 = True
            if flows[1]['tcp_synflags_rev'] is not None and flows[1][
                    'tcp_synflags_rev'] & TCP_SA == TCP_SA:
                conn1 = True

            conditions.append(self.combine_connectivity(conn0, conn1))
 
            if conn1:
                if flows[1]['evilbit_syn_rev']:
                    conditions.append('evilbit.mark.seen')
                else:
                    conditions.append('evilbit.mark.not_seen')
                   
        if self.args.connect == 'dnsudp':
            conn0 = flows[0]['dns_response_valid']     
            conn1 = flows[1]['dns_response_valid']     

            conditions.append(self.combine_connectivity(conn0, conn1))
            if conn1:
                if flows[1]['evilbit_data_rev']:
                    conditions.append('evilbit.mark.seen')
                else:
                    conditions.append('evilbit.mark.not_seen')

        return conditions


