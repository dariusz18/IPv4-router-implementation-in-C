Description: Implements an IPv4 router with support for forwarding, ARP, and ICMP. The router directs packets between networks, obtains MAC addresses using ARP, and handles errors via ICMP messages.

Implemented functions:

get_route: implements LPM, scans the routing table comparing masks with the destination IP, returns the route with the longest mask.

get_mac: searches the ARP table for a given IP, returns true if found, false otherwise.

verify: checks if an IP packet is destined for the router, compares the destination IP with the interface address.

check_sum: checks if TTL is valid, decrements it if valid.

update_eth: updates the IP packet checksum, sets checksum to 0 and recalculates it.

add_arp: adds or updates an entry in the ARP table, checks if the IP already exists.

create: creates an ARP packet, sets Ethernet and ARP fields according to type.

req: creates and sends an ARP request, using the broadcast address as the destination.

reply: creates and sends an ARP reply, using the source MAC from the received request.

procesare: processes the packet queue after receiving an ARP reply, sends packets waiting for the corresponding MAC.

fwd_ipv4: forwards IPv4 packets to the next hop; if the MAC is known, sends directly; otherwise queues the packet and sends an ARP request.

make: initializes an ICMP header, sets type, code, etc.

create_icmp: creates an ICMP packet, builds Ethernet, IP, and ICMP headers, copies the first 8 bytes of the original packet plus IP header, calculates checksum.

error: generates and sends ICMP error messages, uses create_icmp to construct the packet.

main: initializes routing and ARP tables, continuously processes packets, handles IPv4 and ARP packets, maintains a waiting packet queue.
# TCP-UDP-Publish-Subscribe-Server-in-C
# TCP-UDP-Publish-Subscribe-Server-in-C
