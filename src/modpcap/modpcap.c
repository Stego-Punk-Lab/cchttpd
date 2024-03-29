/*
 * ccHTTPd is distributed under the following license:
 *
 * Copyright (c) 2008,2023 Steffen Wendzel <steffen (at) wendzel (dot) de> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must display the following acknowledgement: This product includes software developed by the <copyright holder>.
 * 4. Neither the name of the <copyright holder> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <cwdev/libcwdev.h>

#include "include/modpcap.h"

#include <ctype.h>

int mod_init(void)
{
	/* unused */
	return 0;
}

// /home/wendzel/git/VL_NetSec/uebungen/2021/Blatt1/capture.pcap
// /home/wendzel/git/papers/002_Unfinished/TDSC_DYST/recordings/CS_home_idle_saturday_away.pcap
// /home/wendzel/git/projects/old_projects/xyriahttpd/ip6.pcap

int is_packet_udp_dns(_udphdr *udphdr) {
	return htons(udphdr->uh_sport) == 53 || htons(udphdr->uh_dport) == 53;
}

int is_packet_tcp_dns(_tcphdr *tcphdr) {
	return htons(tcphdr->th_sport) == 53 || htons(tcphdr->th_dport) == 53;
}

int
get_framelen(int datalink)
{
	int framelen;

	switch (datalink) {
		case DLT_NULL:
			framelen = 0;
			break;
		case DLT_LOOP:
			framelen = 4;
			break;
		case DLT_EN10MB:
			framelen = sizeof(struct ether_header);
			break;
		case DLT_IEEE802:
			framelen = 22;
			break;
	#ifdef __linux__
		case DLT_LINUX_SLL:
			framelen = 16;
			break;
	#endif
		case DLT_SLIP:
			framelen = 24;
			break;
		case DLT_PPP:
			framelen = 24;
			break;
		case DLT_FDDI:
			framelen = 2 + 1 + 1 + 6 + 6; /* 16; not tested! */
			break;
	#ifdef DLT_IEEE802_11 /* OpenBSD >= 3.4 */
		case DLT_IEEE802_11:
	#else	/* ifdef DLT_IEEE802 */	/* OpenBSD <= 3.3 -- I wrote this code in 2008 :) */
		case DLT_IEEE802:
	#endif
			framelen = 2 + 2 + 6 + 6 + 6 + 2 + 6; /* 30; not tested! */
			break;
		case DLT_ENC: /* TODO: IPSec */
		default:
			fprintf(stderr, "datalink type %i not supported.\n", datalink);
			return 0;
	}
#ifdef DEBUG
	printf("pcap.framelen=%i\n", framelen);
#endif
	return framelen;
}

void parse_question_name(char extracted_name[256], size_t* current_question_index, const unsigned char* question_region) {
	size_t current_output_pos = 0;
	// TODO add maximum loop count
	// TODO make extracted_name size dynamic
	while (question_region[(*current_question_index)] != 0) {
		if (*current_question_index != 0) {
			// add a dot between labels, but not at the beginning
			if (current_output_pos < 256 - 1) {
				extracted_name[current_output_pos++] = '.';
			}
		}

		// first read the octet length
		size_t octet_length = question_region[(*current_question_index)++];

		// copy the label into the output buffer
		for (size_t i = 0; i < octet_length; i++) {
			if (*current_question_index < 256 - 1) {
				extracted_name[current_output_pos++] = question_region[(*current_question_index)];
			}
			(*current_question_index)++;
		}
	}
	extracted_name[current_output_pos] = '\0';
}

_dns_question*
parse_questions(_dnshdr* dnshdr, size_t* current_question_index) {
	_dns_question *question = NULL;


	// TODO handle multiple questions to return
	for (uint16_t i = 0; i < ntohs(dnshdr->qdcount); i++) {
		// TODO make name dynamic and not hardcoded
		char extracted_name[256];
		question = malloc(sizeof(_dns_question));
		// TODO make offset dynamic (dynamic question region size after one loop)
		question->header_offset = sizeof(_dnshdr);

		const unsigned char *question_region = (unsigned char*) (dnshdr + 1);

		// parse name
		parse_question_name(extracted_name, current_question_index, question_region);
		question->name = malloc(*current_question_index);
		question->name_length = *current_question_index;
		strncpy(question->name, extracted_name, *current_question_index);

		(*current_question_index)++;
		question->qtype = ntohs(*(u_int16_t *)((question_region + *current_question_index)));

		*current_question_index += sizeof(u_int16_t);
		question->qclass = ntohs(*(u_int16_t *)(question_region + *current_question_index));
		*current_question_index += sizeof(u_int16_t);
	}

	return question;
}

void parse_rr_name(const _dns_question* question, _dns_rr *record, const unsigned char* answer_region, size_t* index) {
	const uint8_t c = answer_region[0];
	if ((c & 0xc0) == 0xc0) {
		const size_t pointer_offset = ((c & 0x3f) << 8) + answer_region[1];

		// check if offset is found in questions
		if (question && question->header_offset == pointer_offset) {
			record->name = malloc(question->name_length);
			record->name_length = question->name_length;
			strncpy(record->name, question->name, question->name_length);
		}
		*index += 2;
	} else {
		// TODO read out name like in questions
	}
}

_dns_rr**
parse_resource_records(_dnshdr* dnshdr, u_int16_t count, size_t* region_base_offset, _dns_question* question) {
	_dns_rr *record = NULL;
	_dns_rr **records = malloc(count * sizeof(_dns_rr));

	size_t current_region_index = 0;
	for (uint16_t i = 0; i < count; i++) {
		record = malloc(sizeof(_dns_rr));
		records[i] = record;

		const unsigned char *resource_region = (unsigned char*) (dnshdr + 1) + *region_base_offset + current_region_index;

		parse_rr_name(question, record, resource_region, &current_region_index);

		// now the other fields..
		// TODO this works only if the name is a pointer! otherwise you ned the offset.. but attention at the second+ iteration
		record->type = ntohs(*(u_int16_t *)((resource_region + 2)));
		current_region_index += sizeof(u_int16_t);

		record->class = ntohs(*(u_int16_t *)((resource_region + 4)));
		current_region_index += sizeof(u_int16_t);

		record->ttl = (uint32_t) ntohl(*(u_int32_t *)((resource_region + 6)));
		current_region_index += sizeof(u_int32_t);

		record->rdlength = ntohs(*(u_int16_t *)((resource_region + 10)));
		current_region_index += sizeof(u_int16_t);

		// extract the data
		record->data = malloc(record->rdlength);
		memcpy(record->data, resource_region + 12, record->rdlength);
		current_region_index += record->rdlength;
	}
	*region_base_offset += current_region_index;

	return records;
}

const char* get_dns_type(int type_value) {
	if (type_value >= 0 && type_value < MAX_DNS_TYPES && dnsTypes[type_value]) {
		return dnsTypes[type_value];
	}
	return "";
}

void
handle_dns(_dnshdr *dnshdr, _hdr_descr *hdr_desc)
{
	const char dns_opcode = (dnshdr->opcode == DNS_QUERY ? 'Q' : (dnshdr->opcode == DNS_IQUERY ? 'I' : (dnshdr->opcode == DNS_STATUS ? 'S' : (dnshdr->opcode == DNS_NS_NOTIFY_OP ? 'N' : (dnshdr->opcode == DNS_UPDATE ? 'U' : '?')))));
	
	snprintf(hdr_desc->str_dns_id, sizeof(hdr_desc->str_dns_id) - 1, "0x%x", ntohs(dnshdr->id));
	/* DNS flags combined */
	snprintf(hdr_desc->str_dns_flags, sizeof(hdr_desc->str_dns_flags) - 1, "%s/%s/%s/%s/%s/%s/%s/%s",
		(dnshdr->qr == 1 ? "R" : "Q"),
		(dnshdr->aa == 1 ? "AA" : "-"),
		(dnshdr->tc == 1 ? "TC" : "-"),
		(dnshdr->rd == 1 ? "RD" : "-"),
		(dnshdr->ra == 1 ? "RA" : "-"),
		(dnshdr->unused == 1 ? "Z" : "-"),
		(dnshdr->ad == 1 ? "AD" : "-"),
		(dnshdr->cd == 1 ? "CD" : "-"));
	snprintf(hdr_desc->str_dns_opcode, sizeof(hdr_desc->str_dns_opcode) - 1, "%c", dns_opcode);
	snprintf(hdr_desc->str_dns_rcode, sizeof(hdr_desc->str_dns_rcode) - 1, "%u", dnshdr->rcode);
	/* check for contrained RRs */
	snprintf(hdr_desc->str_dns_qdcount, sizeof(hdr_desc->str_dns_qdcount) - 1, "%d", ntohs(dnshdr->qdcount)); /* #questions */
	snprintf(hdr_desc->str_dns_ancount, sizeof(hdr_desc->str_dns_ancount) - 1, "%d", ntohs(dnshdr->ancount)); /* #ansers */
	snprintf(hdr_desc->str_dns_nscount, sizeof(hdr_desc->str_dns_nscount) - 1, "%d", ntohs(dnshdr->nscount)); /* #auth. entr. */
	snprintf(hdr_desc->str_dns_arcount, sizeof(hdr_desc->str_dns_arcount) - 1, "%d", ntohs(dnshdr->arcount)); /* #add. entr. */

	size_t current_region_index = 0;
	_dns_question* question = parse_questions(dnshdr, &current_region_index);

	// parse answer resource records
	_dns_rr **answers = parse_resource_records(dnshdr, ntohs(dnshdr->ancount), &current_region_index, question);

	// now parse authority
	_dns_rr **authorities = parse_resource_records(dnshdr, ntohs(dnshdr->nscount), &current_region_index, question);

	// finally parse additional
	// TODO needs testing and check for OPT pseudo rr
	//_dns_rr **additionals = parse_resource_records(dnshdr, ntohs(dnshdr->arcount), &current_region_index, question);

	// TODO handle multiple questions
	if (question) {
		snprintf(hdr_desc->str_dns_questions, sizeof(hdr_desc->str_dns_questions) - 1,
		"\"%s,%s,%d\"",
			question->name,
			get_dns_type(question->qtype),
			question->qclass
		);
	}

	if (ntohs(dnshdr->ancount) > 0) {
		// TODO size of buffer dynamic?
		char buffer[1024] = {'\"'};
		for (uint16_t i = 0; i < ntohs(dnshdr->ancount); i++) {
			char tmp_buffer[256];
			const size_t offset = snprintf(tmp_buffer, sizeof(tmp_buffer),
					 "%s,%s,%d,%d,%d,",
					 answers[i]->name,
					 get_dns_type(answers[i]->type),
					 answers[i]->class,
					 answers[i]->ttl,
					 answers[i]->rdlength
			);

			// parse data per type TODO refactor into method
			if (answers[i]->type == 1) {
				inet_ntop(AF_INET, answers[i]->data, tmp_buffer + offset, INET_ADDRSTRLEN);
			} else if (answers[i]->type == 28) {
				// TODO needs testing
				inet_ntop(AF_INET6, answers[i]->data, tmp_buffer + offset, INET6_ADDRSTRLEN);
			} else {
				// send back the raw binary data as fallback
				memcpy(tmp_buffer + offset, answers[i]->data, answers[i]->rdlength);
				tmp_buffer[offset + answers[i]->rdlength] = '\0';
			}

			strcat(buffer, tmp_buffer);
			if (i < ntohs(dnshdr->ancount) - 1) {
				strcat(buffer, "|");
			}
		}

		strcat(buffer, "\"");
		strcpy(hdr_desc->str_dns_answers, buffer);
	}
}

void
handle_tcp(_tcphdr *tcphdr, _hdr_descr *hdr_desc)
{
	snprintf(hdr_desc->str_tcp_sport, sizeof(hdr_desc->str_tcp_sport) - 1, "%u", htons(tcphdr->th_sport));
	snprintf(hdr_desc->str_tcp_dport, sizeof(hdr_desc->str_tcp_dport) - 1, "%u", htons(tcphdr->th_dport));
	snprintf(hdr_desc->str_tcp_seq, sizeof(hdr_desc->str_tcp_seq) - 1, "%u", tcphdr->th_seq);
	snprintf(hdr_desc->str_tcp_ack, sizeof(hdr_desc->str_tcp_ack) - 1, "%u", tcphdr->th_ack);
	snprintf(hdr_desc->str_tcp_off, 3, "%u", tcphdr->th_off);
	snprintf(hdr_desc->str_tcp_flags, 4, "%u", tcphdr->th_flags);
	snprintf(hdr_desc->str_tcp_win, sizeof(hdr_desc->str_tcp_win) - 1, "%u", tcphdr->th_win);
	snprintf(hdr_desc->str_tcp_urp, sizeof(hdr_desc->str_tcp_urp) - 1, "%u", tcphdr->th_urp);
	snprintf(hdr_desc->str_tcp_cksum, sizeof(hdr_desc->str_tcp_cksum) - 1, "%u", htons(tcphdr->th_sum));

	/* handle specific protocols here */
	if (is_packet_tcp_dns(tcphdr)) {
		handle_dns((_dnshdr *)(tcphdr+1), hdr_desc);
	}
}

void
handle_udp(_udphdr *udphdr, _hdr_descr *hdr_desc)
{
	snprintf(hdr_desc->str_udp_sport, sizeof(hdr_desc->str_udp_sport) - 1, "%u", htons(udphdr->uh_sport));
	snprintf(hdr_desc->str_udp_dport, sizeof(hdr_desc->str_udp_dport) - 1, "%u", htons(udphdr->uh_dport));
	snprintf(hdr_desc->str_udp_len, sizeof(hdr_desc->str_udp_len) - 1, "%u", htons(udphdr->uh_ulen));
	snprintf(hdr_desc->str_udp_cksum, sizeof(hdr_desc->str_udp_cksum) - 1, "%u", htons(udphdr->uh_sum));

	/* handle specific protocols here */
	if (is_packet_udp_dns(udphdr)) {
		handle_dns((_dnshdr *)(udphdr+1), hdr_desc);
	}
}

void build_packet_string(struct pcap_pkthdr* hdr, _iphdr* iphdr, int* len_new_pkt_str, _hdr_descr hdr_desc, char new_pkt_str[4096], size_t size) {
	snprintf(new_pkt_str, size - 1,
	         "%ld.%06ld;%u;%u;" /* meta+frame */
	         "%s;%s;" /* l2 and l3 protos */
	         "%s;%s;%s;%s;%s;%s;%s;%s;%s;" /* ip4 */
	         "%s;%s;" /* ip6 */
	         "%s;%s;%s;%s;%s;%s;%s;%s;%s;" /* tcp */
	         "%s;%s;%s;%s;" /* udp */
	         "%s;%s;%s;%s;%s;%s;%s;%s;%s;%s;"/* dns */
	         "\n",
	         /* meta + frame */
	         hdr->ts.tv_sec, hdr->ts.tv_usec, hdr->caplen, hdr->len,
	         /* ethernet and proto types */
	         hdr_desc.str_ether_type,
	         (hdr_desc.str_l3_proto == NULL ? "" : hdr_desc.str_l3_proto),
	         /* ipv4 */
	         (iphdr != NULL ? inet_ntoa(iphdr->ip_src) : ""),
	         (iphdr != NULL ? inet_ntoa(iphdr->ip_dst) : ""),
	         hdr_desc.str_ip_v, hdr_desc.str_ip_hl, hdr_desc.str_ip_tos,
	         hdr_desc.str_ip_id, hdr_desc.str_ip_off, hdr_desc.str_ip_ttl,
	         hdr_desc.str_ip_sum,
	         /* ipv6 */
	         hdr_desc.str_ip6_src, hdr_desc.str_ip6_dst,
	         /* tcp */
	         hdr_desc.str_tcp_sport, hdr_desc.str_tcp_dport,
	         hdr_desc.str_tcp_seq, hdr_desc.str_tcp_ack,
	         hdr_desc.str_tcp_off, hdr_desc.str_tcp_flags,
	         hdr_desc.str_tcp_win, hdr_desc.str_tcp_urp,
	         hdr_desc.str_tcp_cksum,
	         /* udp */
	         hdr_desc.str_udp_sport, hdr_desc.str_udp_dport,
	         hdr_desc.str_udp_len, hdr_desc.str_udp_cksum,
	         /* dns */
	         hdr_desc.str_dns_id, hdr_desc.str_dns_flags,
	         hdr_desc.str_dns_opcode, hdr_desc.str_dns_rcode,
	         hdr_desc.str_dns_qdcount, hdr_desc.str_dns_ancount,
	         hdr_desc.str_dns_nscount, hdr_desc.str_dns_arcount,
	         hdr_desc.str_dns_questions, hdr_desc.str_dns_answers
	);

	*len_new_pkt_str = strlen(new_pkt_str);
}

int
print_pcap_contents(int fd_snd, pcap_t *descr, int limit)
{
	int pcap_next_ex_result = 0;
	const u_char *packet;
	struct pcap_pkthdr *hdr;
	_iphdr *iphdr;
	_ip6hdr*ip6hdr;
	_tcphdr*tcphdr;
	_udphdr *udphdr;
	int datalink;
	int framelen;
	int count = 0;
	struct ether_header *eh;

	char header[] = {
		"num.packets=_________________\n"
		"timestamp;caplen;wirelen;ethertype;l3prot;"
		"ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.cksum;"
		"ip6.src;ip6.dst;"
		"tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;tcp.cksum;"
		"udp.sport;udp.dport;udp.len;udp.cksum;"
		"dns.id;dns.flags;dns.opcode;dns.rcode;dns.questionRRs;dns.answerRRs;dns.authRRs;dns.additRRs;dns.questions;dns.answers;\n"
	   };
#define OUTPUT_SIZE 1024*1024*2 /* 2 MBytes */
	char *output = NULL;
	int output_len_whole = 0,
	    output_len_cur = 0,
	    len_new_pkt_str = 0;
	_hdr_descr hdr_desc;
	char new_pkt_str[4096] = { '\0' };

	
	if ((output = calloc(OUTPUT_SIZE, sizeof(char))) == NULL) {
		perror("calloc(output) in print_pcap_contents()\n");
		return -1;
	}

	datalink = pcap_datalink(descr);
	if ((framelen = get_framelen(datalink)) == 0) {
		fprintf(stderr, "invalid frame length\n");
		free(output);
		return -1;
	}

	memcpy(output, header, strlen(header));
	output_len_whole = output_len_cur = strlen(header);
	
	/* we keep the result returned by pcap_next_ex() to check it later */
	while ((pcap_next_ex_result = pcap_next_ex(descr, &hdr, &packet /* packet data */)) == 1 && count < limit) {
		count++;
		/* start a new packet w/ empty string */
		bzero(new_pkt_str, sizeof(new_pkt_str));
		
		/* reset all pointers and buffers in the hdr_desc*/
		bzero(&hdr_desc, sizeof(hdr_desc));

		iphdr = NULL;
		ip6hdr = NULL;
		tcphdr = NULL;
		udphdr = NULL;
		
		// check size of ether_header is actually given!
		if (hdr->caplen < sizeof(struct ether_header)) {
			fprintf(stderr, "Packet too small for Ethernet header. Skipping.\n");
			break;
		}
		eh = (struct ether_header *) packet;

		switch (htons(eh->ether_type)) {
		case ETHERTYPE_IP:
			// check if iphdr fits into rest of frame b/f cont.
			if (hdr->caplen < (sizeof(struct ether_header) + sizeof(_iphdr))) {
				fprintf(stderr, "Packet too small for IP header. Skipping.\n");
				break;
			}
			iphdr = (_iphdr *) (packet + framelen);
			hdr_desc.str_ether_type = "ip4";

			snprintf(hdr_desc.str_ip_v, 3, "%u", iphdr->ip_v);
			snprintf(hdr_desc.str_ip_hl, 3, "%u", iphdr->ip_hl);

			snprintf(hdr_desc.str_ip_tos, 4, "%u", iphdr->ip_tos);
			snprintf(hdr_desc.str_ip_id, 7, "%u", iphdr->ip_id);
			snprintf(hdr_desc.str_ip_off, 7, "%u", iphdr->ip_off);
			snprintf(hdr_desc.str_ip_ttl, 4, "%u", iphdr->ip_ttl);
			snprintf(hdr_desc.str_ip_sum, 7, "%u", iphdr->ip_sum);

			switch (iphdr->ip_p) {
				case IPPROTO_ICMP:
					hdr_desc.str_l3_proto = "icmp";
					break;
				case IPPROTO_IGMP:
					hdr_desc.str_l3_proto = "igmp";
					break;
				case IPPROTO_TCP:
					hdr_desc.str_l3_proto = "tcp";

					tcphdr = (_tcphdr *) (packet + framelen + (iphdr->ip_hl*4));

					//FIXME: check pkt len to see if it fits tcphdr
					handle_tcp(tcphdr, &hdr_desc);
					break;
				case IPPROTO_UDP:
					hdr_desc.str_l3_proto = "udp";
					udphdr = (_udphdr *) (packet + framelen + (iphdr->ip_hl*4));
					//FIXME: check pkt len to see if it fits udphdr

					handle_udp(udphdr, &hdr_desc);
					break;
				default:
					/* other protocol: TODO: use numeric value */
					hdr_desc.str_l3_proto = "other";
					printf("%hi\n", iphdr->ip_p);
					break;
			}
			break;
		case ETHERTYPE_IPV6:
			// check if iphdr fits into rest of frame b/f cont.
			if (hdr->caplen < (sizeof(struct ether_header) + sizeof(_ip6hdr))) {
				fprintf(stderr, "Packet too small for IP6 header. Skipping.\n");
				break;
			}
			ip6hdr = (_ip6hdr *) (packet + framelen);
			hdr_desc.str_ether_type = "ip6";
			/* convert IPv6 addrs into str */
			if (inet_ntop(AF_INET6, &ip6hdr->ip6_src, hdr_desc.str_ip6_src, sizeof(hdr_desc.str_ip6_src)) == NULL) {
				perror("inet_ntop()");
				free(output);
				return -1;
			}
			if (inet_ntop(AF_INET6, &ip6hdr->ip6_dst, hdr_desc.str_ip6_dst, sizeof(hdr_desc.str_ip6_dst)) == NULL) {
				perror("inet_ntop()");
				free(output);
				return -1;
			}
			switch (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
			case IPPROTO_ICMP:
				hdr_desc.str_l3_proto = "icmp";
				break;
			case IPPROTO_IGMP:
				hdr_desc.str_l3_proto = "igmp";
				break;
			case IPPROTO_TCP:
				hdr_desc.str_l3_proto = "tcp";
				//FIXME: check pkt len to see if it fits tcphdr
				tcphdr = (_tcphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_tcp(tcphdr, &hdr_desc);
				break;
			case IPPROTO_UDP:
				hdr_desc.str_l3_proto = "udp";
				//FIXME: check pkt len to see if it fits udphdr
				udphdr = (_udphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_udp(udphdr, &hdr_desc);
				break;
			case IPPROTO_ICMPV6:
				hdr_desc.str_l3_proto = "icmp6";
				break;
			case 59:
				hdr_desc.str_l3_proto = "ip6-no-next-hdr"; /* IPv6-NoNxt */
				break;
			case 60:
				hdr_desc.str_l3_proto = "ip6-dst-opts";
				break;
			default:
				hdr_desc.str_l3_proto = "other";
				/*printf("%hi (pkt no %i)\n", ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt, count);*/
				break;
			}
			break;
		case ETHERTYPE_ARP:
			hdr_desc.str_ether_type = "arp";
			break;
		default:
			/* other ether type: TODO: use the numeric value */
			hdr_desc.str_ether_type = "other";
#ifdef DEBUG
			printf("ether_type=%hx\n", htons(eh->ether_type));
#endif
			break;
		}

		// build output string for the current packet
		build_packet_string(hdr, iphdr, &len_new_pkt_str, hdr_desc, new_pkt_str, sizeof(new_pkt_str));

		if (output_len_cur > (OUTPUT_SIZE - len_new_pkt_str - 2)) {
			/* output buffer is full: send data and restart filling the buffer from scratch */
			
			/* if this is the first sending, overwrite the num.packets and set them to zero to indicate a huge pcap */
			if (output_len_whole == output_len_cur) {
				snprintf(output, 29, "num.packets=%.16d", 0);
				output[28]='\n';
			}
			//fprintf(stderr, "INTERMEDIATE SENDING!\n");
			cwd_print(fd_snd, output);
			bzero(output, OUTPUT_SIZE);
			output_len_cur = 0;
		}
		/* there is still (or now again!) space in the output buffer: copy new pkt string the output buffer */
		memcpy(output + output_len_cur, new_pkt_str, len_new_pkt_str);
		output_len_cur += len_new_pkt_str;
		output_len_whole += len_new_pkt_str;
	}
	/* check for some errors while parsing:
	 * 0: pkt read from live cap. but timeout;
	 * PCAP_ERROR_BREAK: no more packets;
	 * PCAP_ERROR_NOT_ACTIVATED and PCAP_ERROR can also occur */
	if (pcap_next_ex_result == PCAP_ERROR_NOT_ACTIVATED || pcap_next_ex_result == PCAP_ERROR) {
		fprintf(stderr, "pcap parsing error (packet!=1 returned by pcap_next_ex())!\n");
	} else if (pcap_next_ex_result == PCAP_ERROR_BREAK) {
		; /*fprintf(stderr, "all packets have been read.\n");*/
	}
	/* now put the packet count at the beginning of the string */
	if (output_len_whole == output_len_cur) {
		snprintf(output, 29, "num.packets=%.16d", count);
		output[28]='\n';
	}
	cwd_print(fd_snd, output);
	free(output);
	return 0;
}

int is_filename_safe(int fd_snd, char* filename) {
	/* do not allow '/', '\' and '<' (Javascript) in the filename */
	if (strstr(filename, "/") != NULL || strstr(filename, "\\") != NULL
	    /* check for HTML < == %3c == %3C to catch javascript */
	    || strstr(filename, "<") != NULL || strstr(filename, "%3c") != NULL || strstr(filename, "%3C") != NULL) {
		fprintf(stderr, "requested PCAP filename unsafe (contained '/' or '\\')\n");
		cwd_print(fd_snd, "request rejected!");
		free(filename);
		return 0;
	}
	return 1;
}

void url_decode(char *dst, const char *src) {
	char a, b;
	while (*src) {
		if ((*src == '%') &&
			(((a = src[1])) && ((b = src[2]))) &&
			(isxdigit(a) && isxdigit(b))) {
			if (a >= 'a')
				a -= 'a'-'A';
			if (a >= 'A')
				a -= ('A' - 10);
			else
				a -= '0';
			if (b >= 'a')
				b -= 'a'-'A';
			if (b >= 'A')
				b -= ('A' - 10);
			else
				b -= '0';

			*dst++ = 16*a+b;
			src+=3;
			} else if (*src == '+') {
				*dst++ = ' ';
				src++;
			} else {
				*dst++ = *src++;
			}
	}
	*dst++ = '\0';
}

int get_limit_value(char *query_string) {
	int limit = MODPCAP_FILTER_LIMIT_MAX;
	const char* tmp_value = cwd_get_value_from_var(query_string, "limit");
	if (tmp_value)
		limit = atoi(tmp_value);

	return limit;
}

int set_filter(const int fd_snd, char *query_string, pcap_t *descr) {
	char *filter_string = cwd_get_value_from_var(query_string, "filter");
	if (filter_string)
		url_decode(filter_string, filter_string);

	struct bpf_program filter;
	if (pcap_compile(descr, &filter, filter_string, 0, PCAP_NETMASK_UNKNOWN) != 0) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_string, pcap_geterr(descr));
		cwd_print(fd_snd, ERROR_PCAP_FILTER_SYNTAX);
		return 0;
	}
	if (pcap_setfilter(descr, &filter) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_string, pcap_geterr(descr));
		cwd_print(fd_snd, ERROR_PCAP_FILTER_SYNTAX);
		return 0;
	}
	return 1;
}

pcap_t* get_pcap_handle(char *filename) {
	pcap_t *descr;
	char *filename_full_path = NULL;
	if ((filename_full_path = calloc(sizeof(char), strlen(PCAP_BASEPATH) + strlen(filename) + 1)) == NULL) {
		perror("calloc");
		fprintf(stderr, "calloc()");
		return NULL;
	}
	memcpy(filename_full_path, PCAP_BASEPATH, strlen(PCAP_BASEPATH));
	memcpy(filename_full_path+strlen(PCAP_BASEPATH), filename, strlen(filename));

	char errbuf[PCAP_ERRBUF_SIZE];
	if ((descr = pcap_open_offline(filename_full_path, errbuf)) == NULL) {
#ifdef DEBUG
				fprintf(stderr, "filename: '%s', pcap file: '%s', errbuf='%s'\n", filename, filename_full_path, errbuf);
#endif
		free(filename_full_path);
		return NULL;
	}
	free(filename_full_path);
	return descr;
}

void
mod_reqhandler(int fd_snd, char *query_string)
{
	if (query_string) {
		char *filename;
		if ((filename = cwd_get_value_from_var(query_string, "file"))) {

			if (! is_filename_safe(fd_snd, filename)) return;

			pcap_t *descr;
			if ((descr = get_pcap_handle(filename)) == NULL) return;
			if (! set_filter(fd_snd, query_string, descr)) return;
			const int limit = get_limit_value(query_string);

			if (print_pcap_contents(fd_snd, descr, limit) != 0) {
				cwd_print(fd_snd, ERROR_PCAP_FILE_NOT_OPENED);
			}
			free(filename);
		} else {
			cwd_print(fd_snd, ERROR_PCAP_FILEQUERY_MISSING);
		}
	} else {
		cwd_print(fd_snd, ERROR_PCAP_FILEQUERY_MISSING);
	}
}

