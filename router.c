#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

// Routing table
struct route_table_entry *rtable;
int rtable_len;

// ARP table used for cache
struct arp_table_entry *arptable;
int arptable_len;

// length of queue used for retaining packets
int queue_len;

// ARP Pack used to retain in the queue
struct arp_pack
{
	char packet[MAX_PACKET_LEN];
	int len;
	struct route_table_entry *entry;
};

// TrieNode used for determing the best match
struct TrieNode
{
	struct TrieNode *left, *right;
	// mark if it's the end of a prefix
	int isLeaf;
	struct route_table_entry *entry;
};

// creates a new TrieNode
struct TrieNode *create_new_node()
{
	struct TrieNode *node = malloc(sizeof(struct TrieNode));
	DIE(node == NULL, "memory");

	if (node)
	{
		node->left = NULL;
		node->right = NULL;
		node->isLeaf = 0;
		node->entry = NULL;
	}

	return node;
}

void insert(struct TrieNode *root, struct route_table_entry *entry)
{
	uint32_t prefix = ntohl(entry->prefix);
	uint32_t mask = ntohl(entry->mask);

	struct TrieNode *node = root;

	// we check each bit from the MSB to LSB
	for (int i = 31; i >= 0; i--)
	{
		if (mask & (1 << i))
		{
			int bit = (prefix >> i) & 1;
			
			// if the bit is 0, we are talking about the left child
			if (bit == 0)
			{
				if (node->left == NULL)
				{
					node->left = create_new_node();
				}

				node = node->left;
			}
			
			// if the bit is 1, we are talking about the right child
			if (bit == 1)
			{
				if (node->right == NULL)
				{
					node->right = create_new_node();
				}

				node = node->right;
			}
		}
		else
		{
			// if we get to the 0 section, that means the mask ended, so we
			// stop the searching 
			break;
		}
	}

	node->isLeaf = 1;
	node->entry = entry;
}

// returns the best route using the Trie structure
struct route_table_entry *get_best_route(struct TrieNode *root, uint32_t ip)
{
	// convert ip to host byte order
	uint32_t aux_ip = ntohl(ip);

	struct route_table_entry *match = NULL;
	struct TrieNode *node = root;


	// we check each bit from the MSB to LSB
	for (int i = 31; i >= 0; i--)
	{
		int bit = (aux_ip >> i) & 1;

		// if node is a leaf, then we update the match
		if (node->isLeaf)
		{
			match = node->entry;
		}

		// we try to go onto the next level of the trie, depending on the bit
		// of the ip
		if ((bit == 0) && (node->left != NULL))
		{
			node = node->left;
		}
		else if ((bit == 1) && (node->right != NULL))
		{
			node = node->right;
		}
		else
		{
			// if the node, doesn't have children, we stop the search
			break;
		}
	}

	return match;
}

// checks if the mac given by parameter is a broadcast address
int is_mac_broadcast(uint8_t *mac)
{
	for (int i = 0; i < 6; i++)
	{
		if (mac[i] != 0xFF)
		{
			return 0;
		}
	}

	return 1;
}

// search in cache ip and if it finds it, returns its address
// else, return NULL
struct arp_table_entry *search_cache(uint32_t ip)
{
	for (int i = 0; i < arptable_len; i++)
	{
		// we have found the address searched
		if (arptable[i].ip == ip)
		{
			return &arptable[i];
		}
	}

	// we haven't found the address searched
	return NULL;
}

// adds a new entry in cache (ARP table)
void add_new_entry_cache(uint32_t ip)
{
	arptable[arptable_len].ip = ip;

	// set the mac as a broadcast address
	for (int i = 0; i < 6; i++)
	{
		arptable[arptable_len].mac[i] = 0xFF;
	}

	arptable_len++;
}

// using a static routing table we init the correspondent trie and returns 
// its root
struct TrieNode *init_routing_table_trie(char *path)
{
	rtable = malloc(sizeof(struct route_table_entry) * 100005);
	DIE(rtable == NULL, "memory");

	// we parse the rounting table from the given path
	rtable_len = read_rtable(path, rtable);
	
	// create the trie root
	struct TrieNode *root = create_new_node();

	// adds each entry from the routing table in the trie
	for (int i = 0; i < rtable_len; i++)
	{
		insert(root, &rtable[i]);
	}

	return root;
}

// inits the cache (ARP table)
void init_cache()
{
	arptable = malloc(sizeof(struct arp_table_entry) * 100005);
	DIE(arptable == NULL, "memory");

	// the current length is 0
	arptable_len = 0;
}

// swaps two uint32_t values
void swap_uint32(uint32_t *a, uint32_t *b)
{
	uint32_t aux = *a;
	*a = *b;
	*b = aux;
}

// swaps the mac source and destination addresses in the ether header
void swap_eth_addresses(struct ether_header *eth_hdr)
{
	uint8_t aux_address[6];

	memcpy(aux_address, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, aux_address, 6);
}

// sends an icmp packet of type given
void send_icmp(int interface, char *buf, uint8_t type)
{
	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	DIE(icmp_hdr == NULL, "memory");
	struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	DIE(ip_hdr == NULL, "memory");
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	DIE(eth_hdr == NULL, "memory");

	// the packet is send to its original sender
	swap_eth_addresses(eth_hdr);

	// update the field protocol in the IP header, specifing we have a ICMP packet
	ip_hdr->protocol = IPPROTO_ICMP;

	// swap the source and destination addresses in the IP header
	swap_uint32(&ip_hdr->saddr, &ip_hdr->daddr);

	ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

	// update the fields in the ICMP header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;

	// if type is 0, we should send an "Echo reply"
	if (type == 0)
	{
		struct icmphdr *icmp_hdr_received = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

		uint16_t id = icmp_hdr_received->un.echo.id;
		uint16_t sequence = icmp_hdr_received->un.echo.sequence;

		// set the id and the sequence number from the received ICMP message
		icmp_hdr->un.echo.id = htons(id);
		icmp_hdr->un.echo.sequence = htons(sequence);
	}

	// update the new checksum
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	int total_len = sizeof(struct ether_header) + sizeof(struct iphdr);
	memcpy(buf + total_len, icmp_hdr, sizeof(struct icmphdr));

	// copy the first 8 bytes of the original payload in the IPv4 data
	memcpy(buf + total_len + sizeof(struct icmphdr), buf + total_len, 8);
	total_len += 8 + sizeof(struct icmphdr);

	send_to_link(interface, buf, total_len);

	free(icmp_hdr);
}

// sends an arp replay
void send_arp_response(struct ether_header *eth_hdr, struct arp_header *arp_hdr, int interface)
{
	// swap the source and destination mac addresses in the ethernet header
	swap_eth_addresses(eth_hdr);

	memcpy(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));

	// set sender mac address to the interface given
	get_interface_mac(interface, arp_hdr->sha);

	// swaps the SPA with TPA in the arp header
	uint32_t temp_spa, temp_tpa;
	memcpy(&temp_spa, &arp_hdr->spa, sizeof(uint32_t));
	memcpy(&temp_tpa, &arp_hdr->tpa, sizeof(uint32_t));
	swap_uint32(&temp_spa, &temp_tpa);
	memcpy(&arp_hdr->spa, &temp_spa, sizeof(uint32_t));
	memcpy(&arp_hdr->tpa, &temp_tpa, sizeof(uint32_t));

	memcpy(eth_hdr->ether_shost, arp_hdr->sha, sizeof(arp_hdr->sha));

	// set the operation field to 2 (ARP reply)
	arp_hdr->op = htons(2);

	// calculate the total packet length
	size_t total_len = sizeof(struct ether_header) + sizeof(struct arp_header);

	send_to_link(interface, (char *)eth_hdr, total_len);
}

// queueing an arp pack 
void enqueue_packet_to_queue(queue *packet_queue, char *buf, size_t len, struct route_table_entry *best_route)
{
	struct arp_pack *elem = malloc(sizeof(struct arp_pack));
	DIE(elem == NULL, "memory");

	memcpy(elem->packet, buf, len);
	elem->entry = best_route;
	elem->len = len;

	queue_enq(*packet_queue, elem);
	queue_len++;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// we initialize the trie, the cache and the packet queue
	struct TrieNode *root = init_routing_table_trie(argv[1]);
	DIE(root == NULL, "routing table trie");

	init_cache();
	
	queue_len = 0;
	queue packet_queue = queue_create();
	DIE(packet_queue == NULL, "packet queue");

	while (1)
	{
		int interface;
		size_t len;

		/* We call get_packet to receive a packet. get_packet returns
		the interface it has received the data from. And writes to
		len the size of the packet. */
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* Extract the Ethernet header from the packet. Since protocols are
		 * stacked, the first header is the ethernet header, the next header is
		 * at m.payload + sizeof(struct ether_header) */
		struct ether_header *eth_hdr = (struct ether_header *)buf;

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// we have got an IPv4 packet
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_IP))
		{
			// IPv4 header starts at the address buf + sizeof(struct ether_header)
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// if the router is the destination of the pack
			if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr)
			{
				// he responds to the ICMP messages, so he gives an "Echo Reply"
				send_icmp(interface, buf, 0);
				continue;
			}

			uint16_t old = ntohs(ip_hdr->check);
			ip_hdr->check = 0;

			// if the checksums differs, we should throw the packet
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old)
			{
				continue;
			}

			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
			{
				// sends an ICMP "Time exceeded" message
				send_icmp(interface, buf, 11);
				continue;
			}

			// update the TTL field
			ip_hdr->ttl = ip_hdr->ttl - 1;

			// search the ip adress of the destination in the trie
			struct route_table_entry *best_route = get_best_route(root, ip_hdr->daddr);

			if (best_route == NULL)
			{
				// sends an ICMP "Destination unreachable" message
				send_icmp(interface, buf, 3);
				continue;
			}

			// update the checksum field
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// search the destination address in the cache
			struct arp_table_entry *destination = search_cache(best_route->next_hop);

			// if we find it
			if (destination != NULL)
			{
				// and it's not a broadcast address
				if (!is_mac_broadcast(destination->mac))
				{
					// update the destination address in the ether header
					memcpy(eth_hdr->ether_dhost, destination->mac, 6);
				}
				else
				{
					// it's a broadcast address, so we wait for an ARP response
					// and add it to the waiting queue
					enqueue_packet_to_queue(&packet_queue, buf, len, best_route);
					continue;
				}

				// update the source with the address of the router interface 
				// on which the packet is going to be sent
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);

				send_to_link(best_route->interface, buf, len);
				continue;
			}
			else
			{
				// we sent and ARP request
				char *arp_buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
				DIE(arp_buf == NULL, "memory");

				struct ether_header *request_eth_hdr = (struct ether_header *)arp_buf;

				// the mac address of the destination is a broadcast address
				for (int i = 0; i < 6; i++)
				{
					request_eth_hdr->ether_dhost[i] = 0xFF;
				}

				// add a new entry in the cache
				add_new_entry_cache(best_route->next_hop);

				// add the packet in the queue
				enqueue_packet_to_queue(&packet_queue, buf, len, best_route);

				// the source address is going to be the interface of the router to the next hop
				get_interface_mac(best_route->interface, request_eth_hdr->ether_shost);
				request_eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// we construct an the arp header of the packet that is going to be send
				struct arp_header *request_arp_hdr = (struct arp_header *)(arp_buf + sizeof(struct ether_header));

				request_arp_hdr->htype = htons(1);
				request_arp_hdr->ptype = htons(ETHERTYPE_IP);
				request_arp_hdr->op = htons(1);
				request_arp_hdr->hlen = 6;
				request_arp_hdr->plen = 4;

				memcpy(request_arp_hdr->sha, request_eth_hdr->ether_shost, 6);
				request_arp_hdr->spa = inet_addr(get_interface_ip(best_route->interface));
				request_arp_hdr->tpa = best_route->next_hop;

				send_to_link(best_route->interface, arp_buf, sizeof(struct ether_header) + sizeof(struct arp_header));
				
				free(arp_buf);
				continue;
			}
		}

		// we have got an ARP packet
		if (eth_hdr->ether_type == ntohs(ETHERTYPE_ARP))
		{
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// if it's an request, we should sent a reply
			if (ntohs(arp_hdr->op) == 1)
			{
				send_arp_response(eth_hdr, arp_hdr, interface);
				continue;
			}
			else if (ntohs(arp_hdr->op) == 2)
			{	
				// if it's am reply, we search the address in the cache
				struct arp_table_entry *found = search_cache(arp_hdr->spa);

				// if we find the entry in the cache we find it, we update the mac address
				if (found != NULL)
				{
					memcpy(found->mac, arp_hdr->sha, sizeof(arp_hdr->sha));
				}

				// we try to send the packets that are in the queue
				int aux_len = queue_len;
				for (int i = 0; i < aux_len; i++)
				{
					struct arp_pack *elem = (struct arp_pack *)queue_deq(packet_queue);
					struct ether_header *eth_hdr_aux = (struct ether_header *)elem->packet;

					// we search it in the cache
					struct arp_table_entry *destination = search_cache(elem->entry->next_hop);

					queue_len--;

					// if we find it
					if (destination != NULL)
					{
						// and it's not a broadcast address
						if (!is_mac_broadcast(destination->mac))
						{
							// we send the pachet
							memcpy(eth_hdr_aux->ether_dhost, destination->mac, 6);
							send_to_link(elem->entry->interface, elem->packet, elem->len);
						}
						else
						{
							// if it's still broadcasting, we add it again in the queue
							queue_enq(packet_queue, elem);
							queue_len++;
						}
					}
				}
			}
		}
	}

	return 0;
}
