# IPv4 Router — C

An IPv4 router implemented in C with full support for **packet forwarding**, **ARP**, and **ICMP** error handling.
The router directs packets between networks, resolves MAC addresses using ARP, and communicates errors via ICMP messages.

---

## Project Structure

```
archive/
├── router.c       # Core router logic
├── Makefile
├── README
└── lib/
    ├── lib.c / lib.h       # Infrastructure: send/receive, checksum, routing table parsing
    ├── list.c / list.h     # Linked list implementation
    └── queue.c / queue.h   # Queue implementation (for ARP waiting packets)
```

---

## Implemented Functions

### Routing

| Function | Description |
|---|---|
| `get_route` | **Longest Prefix Match (LPM)** — scans the routing table, compares masks with the destination IP, returns the route with the longest matching mask |
| `fwd_ipv4` | Forwards an IPv4 packet to the next hop — sends directly if MAC is known, otherwise queues the packet and sends an ARP request |

### Validation

| Function | Description |
|---|---|
| `verify` | Checks if an IP packet is destined for the router by comparing the destination IP with the interface address |
| `check_sum` | Validates the IP checksum |
| `check_ttl` | Checks if TTL is valid and decrements it |
| `update_sum` | Recalculates the IP checksum (sets it to 0, then recomputes) |
| `update_eth` | Updates the Ethernet header with new source/destination MAC addresses |

### ARP

| Function | Description |
|---|---|
| `get_mac` | Searches the ARP table for a given IP — returns `true` if found, `false` otherwise |
| `add_arp` | Adds a new entry to the ARP table or updates an existing one |
| `create` | Builds an ARP packet — sets Ethernet and ARP fields according to type (request/reply) |
| `req` | Creates and sends an ARP request using the broadcast address as destination |
| `reply` | Creates and sends an ARP reply using the source MAC from the received request |
| `procesare` | Processes the waiting packet queue after receiving an ARP reply — sends all packets waiting for that MAC |

### ICMP

| Function | Description |
|---|---|
| `make` | Initializes an ICMP header — sets type, code, checksum fields |
| `create_icmp` | Builds a full ICMP error packet: constructs Ethernet, IP, and ICMP headers, copies the first 8 bytes of the original packet + IP header, and recalculates checksums |
| `error` | Generates and sends ICMP error messages using `create_icmp` |

### Entry Point

| Function | Description |
|---|---|
| `main` | Initializes routing and ARP tables, continuously processes incoming packets in a loop, dispatches IPv4/ARP handlers, and maintains the waiting packet queue |

---

## Packet Flow

```
Packet received
      │
      ├── ARP? ──► Request → send reply
      │            Reply   → update ARP table + flush waiting queue
      │
      └── IPv4?
            ├── Destined for router? → drop
            ├── Invalid checksum?    → drop
            ├── TTL expired?         → ICMP Time Exceeded (type 11)
            ├── No route found?      → ICMP Destination Unreachable (type 3)
            └── Forward → MAC known? → send directly
                                NO  → queue packet + send ARP request
```

---

## Design Decisions

- **Waiting queue** — packets that arrive before their next-hop MAC is resolved are held in a queue and flushed automatically once the ARP reply is received
- **LPM routing** — ensures the most specific route is always selected for forwarding
- **Dynamic ARP table** — built at runtime through ARP request/reply exchanges, no static table required
- **ICMP error reporting** — the router notifies senders of TTL expiry and unreachable destinations
