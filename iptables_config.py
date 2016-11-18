#coding: utf-8

import iptc
import uuid

#get_mac_address
def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    return ":".join(mac[e:e+2] for e in range(0, 11, 2))
mac_address = get_mac_address()

#get filter iptables and chain
table = iptc.Table(iptc.Table.FILTER)
chains_list = []
for chain in table.chains:
    chains_list.append(chain.name)
'''
input_chain = chains_list[0]
forward_chain = chains_list[1]
output_chain = chains_list[2]
print input_chain
print forward_chain
print output_chain

#clear filter flush
flush_iptables = table.flush()
'''
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


'''
#change default policy
input_chain = iptc.Policy("INPUT").DROP
forward_chain = iptc.Policy("INPUT").DROP
output_chain = iptc.Policy("INPUT").DROP
'''
