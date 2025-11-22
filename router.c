#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#define NR_MAX_INTRARI 100000

void compare(uint32_t prefix, struct route_table_entry **route, uint32_t *new_mask, struct route_table_entry *rtable_entry, uint32_t mask, uint32_t ip) {
    uint32_t check = mask & ip;
    if (check == prefix && *new_mask <= mask) {
        *new_mask = mask;
        *route = rtable_entry;
    }
}

//LPM
struct route_table_entry *get_route(struct route_table_entry *rtable, int rtable_size, uint32_t ip) {
    struct route_table_entry *route = malloc(sizeof(struct route_table_entry));
    uint32_t new_mask = 0;
    
    for (int i = 0; i < rtable_size; i++) {
        compare(rtable[i].prefix, &route, &new_mask, &rtable[i], rtable[i].mask, ip);
    }
    
    if (new_mask == 0) return NULL;
    return route;
}

//cautare MAC in tabela ARP
bool get_mac(struct arp_table_entry *arp_table, int arp_size, uint32_t ip, uint8_t mac[6]) {
    int ok = 0;
    for (int i = 0; i < arp_size && (ok == 0); i++) {
        if (arp_table[i].ip == ip) {
            for (int j = 0; j < 6; j++) {
                mac[j] = arp_table[i].mac[j];
            }
            ok = 1;
        }
    }
    if (ok == 1) return true;
    return false;
}

bool verify(int interface, struct ip_hdr *ip_hdr) {
   char *ip_str = get_interface_ip(interface);
   uint32_t ip_addr = inet_addr(ip_str);
   
   if (ip_addr == ip_hdr->dest_addr) return true;
   return false;
}

//verific checksum
bool check_sum(struct ip_hdr *ip_hdr) {
   uint16_t sum2 = ip_hdr->checksum;
   ip_hdr->checksum = 0;
   uint16_t sum1 = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
   ip_hdr->checksum = sum2;
   
   if (sum1 == sum2) return true;
   return false;
}

bool check_ttl(struct ip_hdr *ip_hdr) {
   if (ip_hdr->ttl <= 1)
       return false;
   
   ip_hdr->ttl--;
   return true;
}

void update_sum(struct ip_hdr *ip_hdr) {
   ip_hdr->checksum = 0;
   ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
}

void update_eth(int interface, uint8_t next_mac[6], struct ether_hdr *eth) {
   uint8_t mac[6];
   get_interface_mac(interface, mac);
   
   for (int i = 0; i < 6; i++) {
       eth->ethr_dhost[i] = next_mac[i];
       eth->ethr_shost[i] = mac[i];
   }
}

//actualizare intrare ARP
void add_arp(struct arp_table_entry *arp_table, int *arp_size, uint8_t mac[6], uint32_t ip) {
    int ok = 0;
    for (int i = 0; i < *arp_size && (ok == 0); i++) {
        if (arp_table[i].ip == ip) {
            for (int j = 0; j < 6; j++)
                arp_table[i].mac[j] = mac[j];
            ok = 1;
        }
    }    
    arp_table[*arp_size].ip = ip;
    for (int j = 0; j < 6; j++) {
        arp_table[*arp_size].mac[j] = mac[j];
    }
    (*arp_size)++;
}

void create(uint32_t dst_ip, uint8_t *dst_mac, uint16_t arp_op, uint8_t *src_mac, uint32_t src_ip, char *arp_buff) {
   
   struct ether_hdr *eth = (struct ether_hdr *)arp_buff;
   struct arp_hdr *arp = (struct arp_hdr *)(arp_buff + sizeof(struct ether_hdr));
   
   for (int i = 0; i < 6; i++) {
       eth->ethr_shost[i] = src_mac[i];
       eth->ethr_dhost[i] = dst_mac[i];
   }
   eth->ethr_type = htons(0x0806);
   arp->hw_type = htons(1);
   arp->proto_type = htons(0x0800);
   arp->hw_len = 6;
   arp->proto_len = 4;
   arp->opcode = htons(arp_op);
   
   for (int i = 0; i < 6; i++) {
       arp->shwa[i] = src_mac[i];
       if (arp_op == 1) {
           arp->thwa[i] = 0;
       } else {
           arp->thwa[i] = dst_mac[i];
       }
   }
   
   arp->sprotoa = src_ip;
   arp->tprotoa = dst_ip;
}

//trimit ARP request
void req(uint32_t ip_target, int interface) {
   char arp_buff[MAX_PACKET_LEN];
   uint8_t src_mac[6];
   uint8_t bcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   get_interface_mac(interface, src_mac);
   char *ip_str = get_interface_ip(interface);
   uint32_t src_ip = inet_addr(ip_str);
   create(ip_target, bcast, 1, src_mac, src_ip, arp_buff);
   
   send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buff, interface);
}

//trimit ARP reply
void reply(int interface, struct arp_hdr *req_arp) {
   char arp_buff[MAX_PACKET_LEN];
   uint8_t src_mac[6];
   get_interface_mac(interface, src_mac);
   char *ip_str = get_interface_ip(interface);
   uint32_t src_ip = inet_addr(ip_str);
   create(req_arp->sprotoa, req_arp->shwa, 2, src_mac, src_ip, arp_buff);
   
   send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_buff, interface);
}

//procesez coada de pachete
void procesare(struct arp_table_entry *arp_table, int arp_size, int *interfaces, uint32_t ip, uint32_t *ip_addr, size_t *lungimi, 
char pachete[][MAX_PACKET_LEN], int *pkt_cnt) {
   int cnt = 0;
   uint8_t mac[6];
   uint8_t next_mac[6];
   for (int i = 0; i < *pkt_cnt; i++) {
       if (ip == ip_addr[i]) {
           struct ether_hdr *eth = (struct ether_hdr *)pachete[i];
           get_mac(arp_table, arp_size, ip, next_mac);
           get_interface_mac(interfaces[i], mac);
           
           for (int j = 0; j < 6; j++) {
               eth->ethr_shost[j] = mac[j];
               eth->ethr_dhost[j] = next_mac[j];
           }
           send_to_link(lungimi[i], pachete[i], interfaces[i]);
       } else {
           for (int j = 0; j < lungimi[i]; j++) {
               pachete[cnt][j] = pachete[i][j];
           }
           lungimi[cnt] = lungimi[i];
           ip_addr[cnt] = ip_addr[i];
           interfaces[cnt] = interfaces[i];
           cnt++;
       }
   }
   
   *pkt_cnt = cnt;
}

//forwarding pachete IPV4
void fwd_ipv4(struct arp_table_entry *arp_table, int arp_size, int *pkt_cnt, size_t len, char pachete[][MAX_PACKET_LEN], 
int max_packet_len, struct route_table_entry *route, size_t *lungimi, char *buf, uint32_t *ip_addr, int *interfaces) {
    uint8_t next_mac[6];
    struct ether_hdr *eth = (struct ether_hdr *)buf;
    
    if (get_mac(arp_table, arp_size, route->next_hop, next_mac)) {
        update_eth(route->interface, next_mac, eth);
        send_to_link(len, buf, route->interface);
    } else {
        if (*pkt_cnt < max_packet_len) {
            for (int i = 0; i < len; i++)
                pachete[*pkt_cnt][i] = buf[i];
            lungimi[*pkt_cnt] = len;
            ip_addr[*pkt_cnt] = route->next_hop;
            interfaces[*pkt_cnt] = route->interface;
            (*pkt_cnt)++;
            req(route->next_hop, route->interface);
        }
    }
}

//initializare header ICMP
void make(uint8_t code, struct icmp_hdr *icmp, uint8_t type) {
    icmp->mtype = type;
    icmp->mcode = code;
    icmp->check = 0;
    icmp->un_t.echo_t.id = 0;
    icmp->un_t.echo_t.seq = 0;
}

//creare pachet ICMP
void create_icmp(uint8_t cod, char *packet, char *new_icmp, int interfata, uint8_t tip) {

   uint8_t mac[6];
   get_interface_mac(interfata, mac);

   int dim = sizeof(struct ip_hdr) + 8;
   int lung = sizeof(struct icmp_hdr) + dim;
   struct ether_hdr *eth = (struct ether_hdr *)new_icmp;
   struct ether_hdr *sursa = (struct ether_hdr *)packet;
   struct ip_hdr *sursaip = (struct ip_hdr *)(packet + sizeof(struct ether_hdr));
   struct ip_hdr *ip = (struct ip_hdr *)(new_icmp + sizeof(struct ether_hdr));
   struct icmp_hdr *icmp = (struct icmp_hdr *)(new_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
   char *adresa, *dest, *src;
   adresa = get_interface_ip(interfata);
   
   for (int i = 0; i < 6; i++) {
       eth->ethr_dhost[i] = sursa->ethr_shost[i];
       eth->ethr_shost[i] = mac[i];
   }
   eth->ethr_type = htons(0x0800);
   ip->ihl = 5;
   ip->ver = 4;
   ip->tos = 0;
   ip->id = htons(1);
   ip->frag = 0;
   ip->ttl = 64;
   ip->proto = 1;
   ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + dim);
   ip->checksum = 0;
   ip->source_addr = inet_addr(adresa);
   ip->dest_addr = sursaip->source_addr;

   icmp->mtype = tip;
   icmp->mcode = cod;
   icmp->check = 0;
   icmp->un_t.echo_t.id = 0;
   icmp->un_t.echo_t.seq = 0;
   dest = new_icmp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);
   src = packet + sizeof(struct ether_hdr);
   
   for (int i = 0; i < dim; i++) {
       dest[i] = src[i];
   }
   ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
   icmp->check = htons(checksum((uint16_t *)icmp, lung));
}

//mesaj eroare
void error(int interface, char *buf, uint8_t code, uint8_t type, size_t len) {
   int dim, total;
   char pachet[MAX_PACKET_LEN];
   create_icmp(code, buf, pachet, interface, type);
   dim = sizeof(struct ip_hdr) + 8;
   total = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + dim;
   
   send_to_link(total, pachet, interface);
}

int main(int argc, char *argv[])
{
   char buf[MAX_PACKET_LEN];
   char pachete[MAX_PACKET_LEN][MAX_PACKET_LEN];
   size_t lungimi[MAX_PACKET_LEN];
   uint32_t ip_addr[MAX_PACKET_LEN];
   int interfaces[MAX_PACKET_LEN];
   int pkt_cnt = 0;
   int max_packet_len = MAX_PACKET_LEN;
   size_t interface;
   size_t len;
   struct ether_hdr *eth;
   uint16_t packet_type;
   struct ip_hdr *ip;
   struct route_table_entry *route;
   struct arp_hdr *arp;
   uint16_t opcode;
   char *ip_str;
   uint32_t my_ip;
   
   // Do not modify this line
   init(argv + 2, argc - 2);
   struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * NR_MAX_INTRARI);
   struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * NR_MAX_INTRARI);
   int rtable_size = read_rtable(argv[1], rtable);
   int arp_size = 0;
   
   while (1) {
       interface = recv_from_any_link(buf, &len);
       DIE(interface < 0, "recv_from_any_links");

      // TODO: Implement the router forwarding logic

    /* Note that pachete received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
       
       eth = (struct ether_hdr *)buf;
       packet_type = ntohs(eth->ethr_type);
       
       switch (packet_type) {
           case 0x0800:
               ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
               
               if (verify(interface, ip))
                   break;
               if (check_sum(ip) == false)
                   break;
               if (check_ttl(ip) == false) {
                   error(interface, buf, 0, 11, len);
                   break;
               }
               
               route = get_route(rtable, rtable_size, ip->dest_addr);
               if (route == NULL) {
                   error(interface, buf, 0, 3, len);
                   break;
               }
               
               update_sum(ip);
               
               fwd_ipv4(arp_table, arp_size, &pkt_cnt, len, pachete, max_packet_len, route, lungimi, buf, ip_addr, interfaces);
               break;
           
           case 0x0806:
               arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
               opcode = ntohs(arp->opcode);
               if (opcode == 1) {
                   ip_str = get_interface_ip(interface);
                   my_ip = inet_addr(ip_str);
                   if (arp->tprotoa == my_ip) {
                       reply(interface, arp);
                   }
               } 
               else if (opcode == 2) {
                   add_arp(arp_table, &arp_size, arp->shwa, arp->sprotoa);
                   procesare(arp_table, arp_size, interfaces, arp->sprotoa, ip_addr, lungimi, pachete, &pkt_cnt);
               }
               break;
       }
   }
   
   free(rtable);
   free(arp_table);
   return 0;
}