#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "string.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

uint8_t BROADCAST_MAC[6] =  {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct arp_table_entry *arp_table;
int arp_table_size;

queue waiting_packets;

struct queued_packet {
	char *packet;
	int len;
	struct route_table_entry *next_hop;
};

int equal_macs(uint8_t *mac1, uint8_t *mac2) {
	for (int i = 0; i < 6; i++) {
		if (mac1[i] != mac2[i]) {
			return 0;
		}
	}
	return 1;
}


struct trie_node {
	struct route_table_entry *entry;
	struct trie_node *child_0, *child_1;
};
struct trie_node *new_trie_node() {
	struct trie_node *node = malloc(sizeof(struct trie_node));
	DIE(node == NULL, "malloc trie node");

	node->entry = NULL;
	node->child_0 = NULL;
	node->child_1 = NULL;

	return node;
}

struct trie_node *root;
void init_trie(struct route_table_entry *rtable, int rtable_size) {
	root = new_trie_node();

	for (int i = 0; i < rtable_size; i++) {
		struct route_table_entry *current_entry = rtable + i;
		uint32_t current_bit = (1 << 31);
		uint32_t mask = ntohl(current_entry->mask);
		uint32_t prefix = ntohl(current_entry->prefix);
		struct trie_node *current_node = root;
		while (current_bit & mask) {
			if ((prefix & current_bit) == 0) {
				if (current_node->child_0 == NULL) {
					current_node->child_0 = new_trie_node();
				}
				current_node = current_node->child_0;
			} else {
				if (current_node->child_1 == NULL) {
					current_node->child_1 = new_trie_node();
				}
				current_node = current_node->child_1;
			}
			current_bit >>= 1;
		}
		current_node->entry = current_entry;
	}
	
}

struct route_table_entry *find_next_hop(uint32_t destination_ip) {
	struct trie_node *current_node = root;
	struct route_table_entry *best_entry = NULL;
	uint32_t current_bit = (1 << 31);
	while (current_node != NULL) {
		if (current_node->entry != NULL) {
			best_entry = current_node->entry;
		}
		if ((destination_ip & current_bit) == 0) {
			current_node = current_node->child_0;
		} else {
			current_node = current_node->child_1;
		}
		current_bit >>= 1;
	}
	return best_entry;
}

int  get_mac_for_ip(uint32_t ip, uint8_t *mac) {
	// cautam in tabela arp cache
	for (int i = 0; i < arp_table_size; i++) {
		if (arp_table[i].ip == ip) {
			memcpy(mac, arp_table[i].mac, 6);
			return 1;
		}
	}

	return 0;
}

void send_icmp_error(int interface, char *buf, int len, uint8_t type, uint8_t code) {

	char *icmp_reply_buf = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);
	DIE(icmp_reply_buf == NULL, "malloc");

	struct ether_header *new_eth_hdr = (struct ether_header *) icmp_reply_buf;
	struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_reply_buf + sizeof(struct ether_header));
	struct icmphdr *new_icmp_hdr = (struct icmphdr *)(icmp_reply_buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	new_eth_hdr->ether_type = htons(ETHERTYPE_IP);
	memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);

	memcpy(new_ip_hdr, ip_hdr, sizeof(struct iphdr));
	new_ip_hdr->daddr = ip_hdr->saddr;
	new_ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	new_ip_hdr->ttl = 64;
	new_ip_hdr->check = 0;
	new_ip_hdr->protocol = IPPROTO_ICMP;
	new_ip_hdr->tot_len = htons(sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));

	new_icmp_hdr->type = type;
	new_icmp_hdr->code = code;
	new_icmp_hdr->checksum = 0;

	// copiez headerul ip + 8 octeti din pachetul original
	memcpy(icmp_reply_buf + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct ether_header), sizeof(struct iphdr) + 8);
	new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	send_to_link(interface, icmp_reply_buf, sizeof(struct ether_header) + sizeof(struct iphdr) * 2 + sizeof(struct icmphdr) + 8);
	free(icmp_reply_buf);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable;
	int rtable_size;
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "malloc");

	rtable_size = read_rtable(argv[1], rtable);

	init_trie(rtable, rtable_size);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
	DIE(arp_table == NULL, "malloc");

	waiting_packets = queue_create();


	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		uint32_t source_interface_ip = inet_addr(get_interface_ip(interface));

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// bad ether header
		if(len < sizeof(struct ether_header)) {
			continue;
		}

		// verific daca pachetul este pentru mine (sau broadcast)
		uint8_t source_interface_mac[6];
		get_interface_mac(interface, source_interface_mac);
		if (!equal_macs(eth_hdr->ether_dhost, source_interface_mac) && !equal_macs(eth_hdr->ether_dhost, BROADCAST_MAC)) {
			continue;
		}

		// verific tipul pachetului (IP sau ARP)
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			// bad ip header
			if (len < sizeof(struct ether_header) + sizeof(struct iphdr)) {
				continue;
			}

			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			uint32_t destination_ip = ntohl(ip_hdr->daddr);
			// 1. verific daca eu sunt destinatia
			if (ip_hdr->daddr == source_interface_ip && ip_hdr->protocol == IPPROTO_ICMP) {
				// trimit ICMP Echo Reply 
				// copiem mai intai pachetul original
				char *icmp_reply_buf = malloc(len);
				DIE(icmp_reply_buf == NULL, "malloc");

				struct ether_header *new_eth_hdr = (struct ether_header *) icmp_reply_buf;
				struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_reply_buf + sizeof(struct ether_header));

				memcpy(icmp_reply_buf, buf, len);

				// interschimb adresele mac
				memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);

				// interschimb adresele ip
				new_ip_hdr->daddr = ip_hdr->saddr;
				new_ip_hdr->saddr = ip_hdr->daddr;

				// recalculez checksum ip
				new_ip_hdr->check = 0;
				new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, sizeof(struct iphdr)));

				// setez tipul ICMP Echo Reply
				struct icmphdr *icmp_hdr = (struct icmphdr *)(icmp_reply_buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr->type = 0;
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

				// trimit pachetul
				send_to_link(interface, icmp_reply_buf, len);
				free(icmp_reply_buf);
				continue;
			}

			// 2. verific checksum-ul
			uint16_t packet_checksum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t computed_checksum = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			if (packet_checksum != computed_checksum) {
				continue;
			}

			// 3. verific TTL
			if (ip_hdr->ttl <= 1) {
				// trimit ICMP Time Exceeded
				send_icmp_error(interface, buf, len, 11, 0);
				continue;
			} else {
				ip_hdr->ttl--;
			}

			// 4. Caut in tabela de rutare
			struct route_table_entry *next_hop = find_next_hop(destination_ip);
			if (next_hop == NULL) {
				// trimit ICMP Destination Unreachable
				send_icmp_error(interface, buf, len, 3, 0);
				continue;
			}

			// 5. Actualizare checksum
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// 6. Rescriere MAC
			uint8_t new_dest_mac[6];
			uint8_t new_src_mac[6];

			get_interface_mac(next_hop->interface, new_src_mac);
			memcpy(eth_hdr->ether_shost, new_src_mac, 6);

			if (get_mac_for_ip(next_hop->next_hop, new_dest_mac)) {
				memcpy(eth_hdr->ether_dhost, new_dest_mac, 6);
			} else {
				// pun pachetul in coada
				char *queued_packet_buf = malloc(len);
				DIE(queued_packet_buf == NULL, "malloc");
				memcpy(queued_packet_buf, buf, len);

				struct queued_packet *queued_packet = malloc(sizeof(struct queued_packet));
				DIE(queued_packet == NULL, "malloc");

				queued_packet->packet = queued_packet_buf;
				queued_packet->len = len;
				queued_packet->next_hop = next_hop;
				queue_enq(waiting_packets, queued_packet);

				// trimit ARP request
				char *buf_request = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
				DIE(buf_request == NULL, "malloc");

				// completam headerul ethernet
				struct ether_header *eth_hdr = (struct ether_header *) buf_request;
				memcpy(eth_hdr->ether_shost, new_src_mac, 6);
				memcpy(eth_hdr->ether_dhost, BROADCAST_MAC, 6);
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// completam headerul arp
				struct arp_header *arp_hdr = (struct arp_header *)(buf_request + sizeof(struct ether_header));
				arp_hdr->htype = htons(1);
				arp_hdr->ptype = htons(ETHERTYPE_IP);
				arp_hdr->hlen = 6;
				arp_hdr->plen = 4;
				arp_hdr->op = htons(1);
				memcpy(arp_hdr->sha, new_src_mac, 6);
				arp_hdr->spa = inet_addr(get_interface_ip(next_hop->interface));
				memset(arp_hdr->tha, 0, 6);
				arp_hdr->tpa = next_hop->next_hop;

				// trimitem pachetul arp request
				send_to_link(next_hop->interface, buf_request, sizeof(struct ether_header) + sizeof(struct arp_header));
				free(buf_request);
				continue;
			}

			// 7. Trimitere pachet
			send_to_link(next_hop->interface, buf, len);

			

		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_table_entry *new_arp_entry = malloc(sizeof(struct arp_table_entry));
			DIE(new_arp_entry == NULL, "malloc");

			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			if (ntohs(arp_hdr->op) == 1) {
				// ARP request, trebuie sa trimit inapoi reply
				arp_hdr->op = htons(2);

				// schimb adresele mac
				uint8_t new_src_mac[6];
				get_interface_mac(interface, new_src_mac);

				// adresa destinatie e vechea adresa sursa
				memcpy(arp_hdr->tha, arp_hdr->sha, 6);

				// adresa sursa e adresa mea
				memcpy(arp_hdr->sha, new_src_mac, 6);

				// schimb adresele ip
				uint32_t new_src_ip = inet_addr(get_interface_ip(interface));

				// adresa destinatie e adresa sursa
				arp_hdr->tpa = arp_hdr->spa;

				// adresa sursa e adresa mea
				arp_hdr->spa = new_src_ip;

				// interschimb adresele mac de la nivelul ethernet
				memcpy(eth_hdr->ether_shost, new_src_mac, 6);
				memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);

				// trimit pachetul ARP reply
				send_to_link(interface, buf, len);
				continue;
			} else if (ntohs(arp_hdr->op) == 2) {

				// adaug in cache noua intrare
				new_arp_entry->ip = arp_hdr->spa;
				memcpy(new_arp_entry->mac, arp_hdr->sha, 6);
				arp_table[arp_table_size++] = *new_arp_entry;

				// trimit pachetele din coada pentru care se cunoaste acum mac-ul destinatie
				queue aux_queue = queue_create();
				while (!queue_empty(waiting_packets)) {
					struct queued_packet *q_packet = queue_deq(waiting_packets);
					struct ether_header *eth_hdr = (struct ether_header *) q_packet->packet;
					
					uint8_t new_dest_mac[6];
					if (get_mac_for_ip(q_packet->next_hop->next_hop, new_dest_mac)) {
						memcpy(eth_hdr->ether_dhost, new_dest_mac, 6);
						send_to_link(q_packet->next_hop->interface, q_packet->packet, q_packet->len);
						free(q_packet->packet);
						free(q_packet);
					} else {
						queue_enq(aux_queue, q_packet);
					}

				}
				waiting_packets = aux_queue;
			}
		} else {
			continue;
		}

	}
}

