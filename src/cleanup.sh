#!/bin/bash

#===============================================================================
#   SOURCE:         cleanup.sh
#
#   PROGRAMMER:     Alex Zielinski
#
#   DATE:           Feb 1, 2018
#
#   DESCRIPTION:    This shell script resets firewall configurations
#                       > Flush all chains
#                       > Delete all user defined chains
#                       > Set default chain policy to ACCEPT
#===============================================================================

iptables --flush
iptables --delete-chain
iptables --policy INPUT ACCEPT
iptables --policy OUTPUT ACCEPT
iptables --policy FORWARD ACCEPT
