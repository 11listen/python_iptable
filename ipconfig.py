#coding: utf-8

import iptc
import uuid

#get_mac_address
def get_mac_address():
    node = uuid.getnode()
    mac = uuid.UUID(int=node).hex[-12:]
    return ":".join(mac[e:e+2] for e in range(0, 11, 2))
mac_address = get_mac_address()
'''
#change default policy
table = iptc.Table(iptc.Table.FILTER)
input_chain = iptc.Chain(table, "INPUT")
#forward_chain = iptc.Chain(table, "FORWARD")
#output_chain = iptc.Chain(table, "OUTPUT")
pol = iptc.Policy("DROP")
input_chain.set_policy(pol)
#forward_chain.set_policy(pol)
#output_chain.set_policy(pol)
'''
#clear filter flush
table = iptc.Table(iptc.Table.FILTER)
flush_input = iptc.Chain(table, 'INPUT').flush()
flush_forward = iptc.Chain(table, 'FORWARD').flush()
nat_table = iptc.Table(iptc.Table.NAT)
flush_nat = iptc.Chain(nat_table, 'POSTROUTING').flush()

#define rules connection state
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match = iptc.Match(rule, "tcp")
match.dport = "22"
rule.add_match(match)
match = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match.state = "NEW,RELATED,ESTABLISHED"
rule.add_match(match)
chain.insert_rule(rule)

#open more port
#http
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match_http = iptc.Match(rule, "tcp")
match_http.dport = "80"
rule.add_match(match_http)
match_http = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match_http.state = "NEW,RELATED,ESTABLISHED"
rule.add_match(match_http)
chain.insert_rule(rule)

#https
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match_https = iptc.Match(rule, "tcp")
match_https.dport = "443"
rule.add_match(match_https)
match_https = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match_https.state = "NEW,RELATED,ESTABLISHED"
rule.add_match(match_https)
chain.insert_rule(rule)

#mysql
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match_login = iptc.Match(rule, "tcp")
match_login.dport = "3306"
rule.add_match(match_login)
match_login = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match_login.state = "NEW,RELATED,ESTABLISHED"
rule.add_match(match_login)
chain.insert_rule(rule)

#telnet
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "ACCEPT")
match_telnet = iptc.Match(rule, "tcp")
match_telnet.dport = "23"
rule.add_match(match_telnet)
match_telnet = iptc.Match(rule, "state")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
match_telnet.state = "NEW,RELATED,ESTABLISHED"
rule.add_match(match_telnet)
chain.insert_rule(rule)

#filter packet header
#ALL FIN,URG,PSH
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_a = iptc.Match(rule, "tcp")
match_a.tcp_flags = "ALL FIN,URG,PSH"
rule.add_match(match_a)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#ALL SYN,RST,ACK,FIN,URG
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_b = iptc.Match(rule, "tcp")
match_b.tcp_flags = "ALL SYN,RST,ACK,FIN,URG"
rule.add_match(match_b)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#ALL NONE
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_c = iptc.Match(rule, "tcp")
match_c.tcp_flags = "ALL NONE"
rule.add_match(match_c)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#SYN,RST SYN,RST
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_c = iptc.Match(rule, "tcp")
match_c.tcp_flags = "SYN,RST SYN,RST"
rule.add_match(match_c)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#SYN,FIN SYN,FIN
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_d = iptc.Match(rule, "tcp")
match_d.tcp_flags = "SYN,FIN SYN,FIN"
rule.add_match(match_d)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#ALL FIN,URG,PSH
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_e = iptc.Match(rule, "tcp")
match_e.tcp_flags = "ALL FIN,URG,PSH"
rule.add_match(match_e)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#ALL SYN,RST,ACK,FIN,URG
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_f = iptc.Match(rule, "tcp")
match_f.tcp_flags = "ALL SYN,RST,ACK,FIN,URG"
rule.add_match(match_f)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#ALL NONE
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_g = iptc.Match(rule, "tcp")
match_g.tcp_flags = "ALL NONE"
rule.add_match(match_g)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#SYN,RST SYN,RST
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_h = iptc.Match(rule, "tcp")
match_h.tcp_flags = "SYN,RST SYN,RST"
rule.add_match(match_h)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

#SYN,FIN SYN,FIN
rule = iptc.Rule()
rule.protocol = "tcp"
rule.target = iptc.Target(rule, "DROP")
match_k = iptc.Match(rule, "tcp")
match_k.tcp_flags = "SYN,FIN SYN,FIN"
rule.add_match(match_c)
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
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
rule.src = "172.10.1.0/255.255.255.0"
rule.dst = "192.168.0.0/255.255.255.0"
t = rule.create_target('SNAT')
t.to_source = "192.168.0.107"
chain.insert_rule(rule)

#define forward rule
rule = iptc.Rule()
rule.target = iptc.Target(rule, "ACCEPT")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
#rule.in_interface = 'eth0'
#rule.out_interface = 'eth1'
rule.protocol = 'tcp'
match_http = iptc.Match(rule, "tcp")
match_https = iptc.Match(rule, "tcp")
match_http.dport = "80"
match_https.dport = "443"
rule.dst = "192.168.0.109"
rule.add_match(match_http)
rule.add_match(match_https)
chain.insert_rule(rule)
'''
#limit maximum
rule = iptc.Rule()
rule.protocol = 'tcp'
rule.target = iptc.Target(rule, "DROP")
rule.in_interface = 'eth0'
match_s = iptc.Match(rule, "tcp")
match_s.tcp_flags = 'FIN,SYN,RST,ACK SYN'
match_s.connlimit_above = '15'
rule.add_match(match_s)
chain_s = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain_s.insert_rule(rule)
'''

#load log
rule = iptc.Rule()
rule.target = iptc.Target(rule, "LOG")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)
