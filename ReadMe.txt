Linux_Firewall_1
----------------

This is a simple IPTables Linux firewall script developed with bash.

The characteristics of the firewall is as follows:

  > Set default policy to DROP

  > Create a set of rules that will:
    - Permit inbound/outbound SSH packets
    - Permit inbound/outbound WWW packets
    - Drop inbound traffic to port 80 from source ports less than 1024
    - Drop all incoming packets from reserved port 0 as well as outbound traffic
      to port 0

  > Create a set of user-defined chans that will implement accounting rules to
    keep track of www and ssh traffic versus the rest of the traffic on your system

  > Drop all inbound SYN packets unless there is a rule that permits the inbound traffic

  > Remember to allow DNS and DHCP traffic

Please read the Design Doc for further details.