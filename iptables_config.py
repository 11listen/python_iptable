#coding: utf-8

import iptc
import uuid

#get_mac_address
def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    return ":".join(mac[e:e+2] for e in range(0, 11, 2))
mac_address = get_mac_address()

#change default policy
table = iptc.Table(iptc.Table.FILTER)
input_chain = iptc.Chain(table, "INPUT")
forward_chain = iptc.Chain(table, "FORWARD")
#output_chain = iptc.Chain(table, "OUTPUT")
pol = iptc.Policy("DROP")
input_chain.set_policy(pol)
forward_chain.set_policy(pol)
#output_chain.set_policy(pol)

#clear filter flush
table = iptc.Table(iptc.Table.FILTER)
flush_input = iptc.Chain(table, 'INPUT').flush()
flush_forward = iptc.Chain(table, 'FORWARD').flush()
nat_table = iptc.Table(iptc.Table.NAT)
flush_nat = iptc.Chain(nat_table, 'POSTROUTING').flush()


#define rules connection state
rule = iptc.Rule()
rule.Protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match.state = "RELATED,ESTABLISHED"
rule.add_match(match)
chain.insert_rule(rule)

#binding mac
rule = iptc.Rule()
match = iptc.Match(rule,"mac")
match.mac_source = mac_address
rule.add_match(match)
rule.target = iptc.Target(rule, "ACCEPT")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#config snat
chain = iptc.Chain(iptc.Table('nat'), 'POSTROUTING')
rule = iptc.Rule()
rule.out_interface = 'eth0'
rule.src = "192.168.0.0/255.255.255.0"
t = rule.create_target('SNAT')
t.to_source = "192.168.0.104"
chain.insert_rule(rule)

#define forward rule
rule = iptc.Rule()
rule.target = iptc.Target(rule, "ACCEPT")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
rule.in_interface = 'eth0'
rule.out_interface = 'eth1'
rule.protocol = 'tcp'
match = iptc.Match(rule, "tcp")
match.dport = "80"
rule.dst = "192.168.0.104"
rule.add_match(match)
chain.insert_rule(rule)
