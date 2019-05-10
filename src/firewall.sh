#!/bin/bash

#===============================================================================
#   SOURCE:         firewall.sh
#
#   PROGRAMMER:     Alex Zielinski
#
#   DATE:           Feb 1, 2018
#
#   DESCRIPTION:    This shell script configures a firewall using 'iptables' and
#                   'netfilter'. The firewall is configured as follows:
#                       > Accept inbound/outbound SSH traffic
#                       > Accept inbound/outbound WWW traffic
#                       > Accept inbound/outbound DNS traffic
#                       > Accept inbound/outbound DHCP traffic
#                       > Drop inbound traffic to port 80 with source port < 1024
#                       > Drop all port 0 Traffic
#                       > Drop inbound SYN packets
#===============================================================================


#===============================================================================
#                               ---- Setup ----
# delete rules of all chains
iptables --flush

# delete all none built-in chains
iptables --delete-chain

# set default policies of all chains to DROP
iptables --policy INPUT DROP
iptables --policy OUTPUT DROP
iptables --policy FORWARD DROP

# create user defined chains for inbound and outbound IP accounting
iptables --new-chain WWW_ACCT
iptables --new-chain SSH_ACCT
iptables --new-chain OTHER_ACCT

# Add accounting rules to user defined chains
iptables --append WWW_ACCT --protocol TCP
iptables --append WWW_ACCT --protocol UDP
iptables --append SSH_ACCT --protocol TCP
iptables --append SSH_ACCT --protocol UDP
iptables --append OTHER_ACCT

# User defined seciton
USER_PORTS=();

#===============================================================================


#===============================================================================
#                      ---- Open User Defined Ports ----

for port in ${USER_PORTS[@]}
do
    iptables --append INPUT --protocol TCP --dport $port --jump ACCEPT
    iptables --append INPUT --protocol TCP --sport $port --jump ACCEPT
    iptables --append INPUT --protocol UDP --dport $port --jump ACCEPT
    iptables --append INPUT --protocol UDP --sport $port --jump ACCEPT
    iptables --append OUTPUT --protocol TCP --dport $port --jump ACCEPT
    iptables --append OUTPUT --protocol TCP --sport $port --jump ACCEPT
    iptables --append OUTPUT --protocol UDP --dport $port --jump ACCEPT
    iptables --append OUTPUT --protocol UDP --sport $port --jump ACCEPT
done
#===============================================================================


#===============================================================================
#             ---- Add Rules to SSH Traffic Accounting Chain ----

# ACCEPT SSH traffic
iptables --append SSH_ACCT --protocol TCP --sport 22 --jump ACCEPT
iptables --append SSH_ACCT --protocol TCP --dport 22 --jump ACCEPT
iptables --append SSH_ACCT --protocol UDP --sport 22 --jump ACCEPT
iptables --append SSH_ACCT --protocol UDP --dport 22 --jump ACCEPT
#===============================================================================


#===============================================================================
#             ---- Add Rules to Web Traffic Accounting Chain ----

# DROP inbound HTTP traffic with source port < 1024
iptables --append WWW_ACCT --protocol TCP --dport 80 --sport 0:1023 --jump DROP
iptables --append WWW_ACCT --protocol UDP --dport 80 --sport 0:1023 --jump DROP

# ACCEPT HTTP traffic
iptables --append WWW_ACCT --protocol TCP --dport 80 --jump ACCEPT
iptables --append WWW_ACCT --protocol TCP --sport 80 --jump ACCEPT
iptables --append WWW_ACCT --protocol UDP --dport 80 --jump ACCEPT
iptables --append WWW_ACCT --protocol UDP --sport 80 --jump ACCEPT

# ACCEPT HTTPS traffic
iptables --append WWW_ACCT --protocol TCP --dport 443 --jump ACCEPT
iptables --append WWW_ACCT --protocol TCP --sport 443 --jump ACCEPT
iptables --append WWW_ACCT --protocol UDP --dport 443 --jump ACCEPT
iptables --append WWW_ACCT --protocol UDP --sport 443 --jump ACCEPT
#===============================================================================


#===============================================================================
#             ---- Add Rules to Other Traffic Accounting Chain ----

# DROP packets with source port 0 or dest port 0 (TCP and UDP)
iptables --append OTHER_ACCT --protocol TCP --sport 0 --jump DROP
iptables --append OTHER_ACCT --protocol TCP --dport 0 --jump DROP
iptables --append OTHER_ACCT --protocol UDP --sport 0 --jump DROP
iptables --append OTHER_ACCT --protocol UDP --dport 0 --jump DROP

# ACCEPT DNS traffic
iptables --append OTHER_ACCT --protocol TCP --dport 53 --jump ACCEPT
iptables --append OTHER_ACCT --protocol TCP --sport 53 --jump ACCEPT
iptables --append OTHER_ACCT --protocol UDP --dport 53 --jump ACCEPT
iptables --append OTHER_ACCT --protocol UDP --sport 53 --jump ACCEPT

# ACCEPT DHCP traffic
iptables --append OTHER_ACCT --protocol UDP --dport 67:68 --sport 67:68 --jump ACCEPT
#===============================================================================


#===============================================================================
#            ---- Forward SSH Traffic to SSH Accounting Chain ----

# Forward inbound packets with source port 0 or dest port 0 to SSH_ACCT
iptables --append INPUT --protocol TCP --sport 22 --jump SSH_ACCT
iptables --append INPUT --protocol TCP --dport 22 --jump SSH_ACCT
iptables --append INPUT --protocol UDP --sport 22 --jump SSH_ACCT
iptables --append INPUT --protocol UDP --dport 22 --jump SSH_ACCT

# Forward outbound packets with source port 0 or dest port 0 to SSH_ACCT
iptables --append OUTPUT --protocol TCP --sport 22 --jump SSH_ACCT
iptables --append OUTPUT --protocol TCP --dport 22 --jump SSH_ACCT
iptables --append OUTPUT --protocol UDP --sport 22 --jump SSH_ACCT
iptables --append OUTPUT --protocol UDP --dport 22 --jump SSH_ACCT
#===============================================================================


#===============================================================================
#            ---- Forward Web Traffic to Web Accounting Chain ----

# Forward inbound HTTP traffic to WEB_ACCT
iptables --append INPUT --protocol TCP --dport 80 --jump WWW_ACCT
iptables --append INPUT --protocol TCP --sport 80 --jump WWW_ACCT
iptables --append INPUT --protocol UDP --dport 80 --jump WWW_ACCT
iptables --append INPUT --protocol UDP --sport 80 --jump WWW_ACCT

# Forward outbound HTTP traffic to WEB_ACCT
iptables --append OUTPUT --protocol TCP --dport 80 --jump WWW_ACCT
iptables --append OUTPUT --protocol TCP --sport 80 --jump WWW_ACCT
iptables --append OUTPUT --protocol UDP --dport 80 --jump WWW_ACCT
iptables --append OUTPUT --protocol UDP --sport 80 --jump WWW_ACCT

# Forward inbound HTTPS traffic to WEB_ACCT
iptables --append INPUT --protocol TCP --dport 443 --jump WWW_ACCT
iptables --append INPUT --protocol TCP --sport 443 --jump WWW_ACCT
iptables --append INPUT --protocol UDP --dport 443 --jump WWW_ACCT
iptables --append INPUT --protocol UDP --sport 443 --jump WWW_ACCT

# Forward outbound HTTPS traffic to WEB_ACCT
iptables --append OUTPUT --protocol TCP --dport 443 --jump WWW_ACCT
iptables --append OUTPUT --protocol TCP --sport 443 --jump WWW_ACCT
iptables --append OUTPUT --protocol UDP --dport 443 --jump WWW_ACCT
iptables --append OUTPUT --protocol UDP --sport 443 --jump WWW_ACCT
#===============================================================================


#===============================================================================
#          ---- Forward Other Traffic to Other Accounting Chain ----

# Forward inbound packets with source port 0 or dest port 0 to OTHER_ACCT
iptables --append INPUT --protocol TCP --sport 0 --jump OTHER_ACCT
iptables --append INPUT --protocol TCP --dport 0 --jump OTHER_ACCT
iptables --append INPUT --protocol UDP --sport 0 --jump OTHER_ACCT
iptables --append INPUT --protocol UDP --dport 0 --jump OTHER_ACCT

# Forward outbound packets with source port 0 or dest port 0 to OTHER_ACCT
iptables --append OUTPUT --protocol TCP --sport 0 --jump OTHER_ACCT
iptables --append OUTPUT --protocol TCP --dport 0 --jump OTHER_ACCT
iptables --append OUTPUT --protocol UDP --sport 0 --jump OTHER_ACCT
iptables --append OUTPUT --protocol UDP --dport 0 --jump OTHER_ACCT

# Forward inbound DNS traffic to OTHER_ACCT
iptables --append INPUT --protocol TCP --dport 53 --jump OTHER_ACCT
iptables --append INPUT --protocol TCP --sport 53 --jump OTHER_ACCT
iptables --append INPUT --protocol UDP --dport 53 --jump OTHER_ACCT
iptables --append INPUT --protocol UDP --sport 53 --jump OTHER_ACCT

# Forward outbound DNS traffic to OTHER_ACCT
iptables --append OUTPUT --protocol TCP --dport 53 --jump OTHER_ACCT
iptables --append OUTPUT --protocol TCP --sport 53 --jump OTHER_ACCT
iptables --append OUTPUT --protocol UDP --dport 53 --jump OTHER_ACCT
iptables --append OUTPUT --protocol UDP --sport 53 --jump OTHER_ACCT

# Forward DHCP traffic to OTHER_ACCT
iptables --append INPUT --protocol UDP --dport 67:68 --sport 67:68 --jump OTHER_ACCT

# Forward all other traffic to OTHER_ACCT
iptables --append INPUT --protocol TCP --jump OTHER_ACCT
iptables --append INPUT --protocol UDP --jump OTHER_ACCT
iptables --append OUTPUT --protocol TCP --jump OTHER_ACCT
iptables --append OUTPUT --protocol UDP --jump OTHER_ACCT
#===============================================================================
