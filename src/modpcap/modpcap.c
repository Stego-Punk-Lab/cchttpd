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

#define SKIP_PKT_DNT_CNT	count--; /* packet doesn't count */; continue; /* skip */

int mod_init(void)
{
	/* unused */
	return 0;
}

// /home/wendzel/git/VL_NetSec/uebungen/2021/Blatt1/capture.pcap
// /home/wendzel/git/papers/002_Unfinished/TDSC_DYST/recordings/CS_home_idle_saturday_away.pcap
// /home/wendzel/git/projects/old_projects/xyriahttpd/ip6.pcap

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

void
handle_dns(_dnshdr *dnshdr, _hdr_descr *hdr_desc)
{
	char dns_opcode = (dnshdr->opcode == DNS_QUERY ? 'Q' : (dnshdr->opcode == DNS_IQUERY ? 'I' : (dnshdr->opcode == DNS_STATUS ? 'S' : (dnshdr->opcode == DNS_NS_NOTIFY_OP ? 'N' : (dnshdr->opcode == DNS_UPDATE ? 'U' : '?')))));
	
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
}

void
handle_tcp(_tcphdr *tcphdr, _hdr_descr *hdr_desc, _pcap_filter *filter)
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
	if (htons(tcphdr->th_sport) == 53 || htons(tcphdr->th_dport) == 53) {
		/* point to area brhind the UDP hdr */
		// TODO: is the captured frame still big enough?
		if (filter->dns == 1) {
			handle_dns((_dnshdr *)(tcphdr+1), hdr_desc);
		}
	}
}

void
handle_udp(_udphdr *udphdr, _hdr_descr *hdr_desc, _pcap_filter *filter)
{
	snprintf(hdr_desc->str_udp_sport, sizeof(hdr_desc->str_udp_sport) - 1, "%u", htons(udphdr->uh_sport));
	snprintf(hdr_desc->str_udp_dport, sizeof(hdr_desc->str_udp_dport) - 1, "%u", htons(udphdr->uh_dport));
	snprintf(hdr_desc->str_udp_len, sizeof(hdr_desc->str_udp_len) - 1, "%u", htons(udphdr->uh_ulen));
	snprintf(hdr_desc->str_udp_cksum, sizeof(hdr_desc->str_udp_cksum) - 1, "%u", htons(udphdr->uh_sum));
	/* handle specific protocols here */
	if (htons(udphdr->uh_sport) == 53 || htons(udphdr->uh_dport) == 53) {
		/* point to area brhind the UDP hdr */
		// TODO: check size of HDP hdr (does it contain data through uh_uhlen?) [could be incorrectly set on purpose!] or [better!] is the captured frame still big enough?
		if (filter->dns == 1) {
			handle_dns((_dnshdr *)(udphdr+1), hdr_desc);
		}
	}
}

int
print_pcap_contents(int fd_snd, char *filename, _pcap_filter filter)
{
	pcap_t *descr;
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
	char errbuf[PCAP_ERRBUF_SIZE];
	char header[] = {
		"num.packets=_________________\n"
		"timestamp;caplen;wirelen;ethertype;l3prot;"
		"ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.sum_raw;"
		"ip6.src;ip6.dst;"
		"tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;"
		"udp.sport;udp.dport;udp.len;udp.cksum;"
		"dns.id;dns.flags;dns.opcode;dns.rcode;dns.questionRRs;dns.answerRRs;dns.authRRs;dns.additRRs;\n"
	   };
#define OUTPUT_SIZE 1024*1024*2 /* 2 MBytes */
	char *output = NULL;
	int output_len_whole = 0,
	    output_len_cur = 0,
	    len_new_pkt_str = 0;
	_hdr_descr hdr_desc;
	char new_pkt_str[4096] = { '\0' };
	char *filename_full_path = NULL;
	
	if ((output = calloc(OUTPUT_SIZE, sizeof(char))) == NULL) {
		perror("calloc(output) in print_pcap_contents()\n");
		return -1;
	}
	
	if ((filename_full_path = calloc(sizeof(char), strlen(PCAP_BASEPATH) + strlen(filename) + 1)) == NULL) {
		perror("calloc");
		fprintf(stderr, "calloc()");
		free(output);
		return -1;
	}
	memcpy(filename_full_path, PCAP_BASEPATH, strlen(PCAP_BASEPATH));
	memcpy(filename_full_path+strlen(PCAP_BASEPATH), filename, strlen(filename));

	if ((descr = pcap_open_offline(filename_full_path, errbuf)) == NULL) {
#ifdef DEBUG
		fprintf(stderr, "filename: '%s', pcap file: '%s', errbuf='%s'\n", filename, filename_full_path, errbuf);
#endif
		free(filename_full_path);
		free(output);
		return -1;
	}
	free(filename_full_path);

	datalink = pcap_datalink(descr);
	if ((framelen = get_framelen(datalink)) == 0) {
		fprintf(stderr, "invalid frame length\n");
		free(output);
		return -1;
	}

	memcpy(output, header, strlen(header));
	output_len_whole = output_len_cur = strlen(header);
	
	/* we keep the result returned by pcap_next_ex() to check it later */
	while ((pcap_next_ex_result = pcap_next_ex(descr, &hdr, &packet /* packet data */)) == 1 && count < filter.limit) {
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
			if (filter.ip4 == 0) {
				SKIP_PKT_DNT_CNT
			}
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
			case 1:
				if (filter.icmp4 == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "icmp";
				break;
			case 2:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "igmp";
				break;
			case 6:
				if (filter.tcp == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "tcp";
				tcphdr = (_tcphdr *) (packet + framelen + (iphdr->ip_hl*4));
				//FIXME: check pkt len to see if it fits tcphdr
				handle_tcp(tcphdr, &hdr_desc, &filter);
				break;
			case 17:
				if (filter.udp == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "udp";
				udphdr = (_udphdr *) (packet + framelen + (iphdr->ip_hl*4));
				//FIXME: check pkt len to see if it fits udphdr
				handle_udp(udphdr, &hdr_desc, &filter);
				break;
			default:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}
				/* other protocol: TODO: use numeric value */
				hdr_desc.str_l3_proto = "other";
				printf("%hi\n", iphdr->ip_p);
				break;
			}
			break;
		case ETHERTYPE_IPV6:
			if (filter.ip6 == 0) {
				SKIP_PKT_DNT_CNT
			}
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
			case 1:
				if (filter.icmp4 == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "icmp";
				break;
			case 2:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}

				hdr_desc.str_l3_proto = "igmp";
				break;
			case 6:
				if (filter.tcp == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "tcp";
				//FIXME: check pkt len to see if it fits tcphdr
				tcphdr = (_tcphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_tcp(tcphdr, &hdr_desc, &filter);
				break;
			case 17:
				if (filter.udp == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "udp";
				//FIXME: check pkt len to see if it fits udphdr
				udphdr = (_udphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_udp(udphdr, &hdr_desc, &filter);
				break;
			case 58:
				if (filter.icmp6 == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "icmp6";
				break;
			case 59:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "ip6-no-next-hdr"; /* IPv6-NoNxt */
				break;
			case 60:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "ip6-dst-opts";
				break;
			default:
				if (filter.others == 0) {
					SKIP_PKT_DNT_CNT
				}
				hdr_desc.str_l3_proto = "other";
				/*printf("%hi (pkt no %i)\n", ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt, count);*/
				break;
			}
			break;
		case ETHERTYPE_ARP:
			if (filter.others == 0)
				SKIP_PKT_DNT_CNT
			
			hdr_desc.str_ether_type = "arp";
			break;
		default:
			/* other ether type: TODO: use the numeric value */
			if (filter.others == 0)
				SKIP_PKT_DNT_CNT
			
			hdr_desc.str_ether_type = "other";
#ifdef DEBUG
			printf("ether_type=%hx\n", htons(eh->ether_type));
#endif
			break;
		}
		snprintf(new_pkt_str, sizeof(new_pkt_str) - 1,
			"%ld.%06ld;%u;%u;" /* meta+frame */
			"%s;%s;" /* l2 and l3 protos */
			"%s;%s;%s;%s;%s;%s;%s;%s;%s;" /* ip4 */
			"%s;%s;" /* ip6 */
			"%s;%s;%s;%s;%s;%s;%s;%s;%s;" /* tcp */
			"%s;%s;%s;%s;" /* udp */
			"%s;%s;%s;%s;%s;%s;%s;%s"/* dns */
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
			   hdr_desc.str_dns_nscount, hdr_desc.str_dns_arcount
			);
		
		len_new_pkt_str = strlen(new_pkt_str);
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

void
mod_reqhandler(int fd_snd, char *query_string)
{
	_pcap_filter filter;
	
	if (query_string) {
		char *filename;
		if ((filename = cwd_get_value_from_var(query_string, "file"))) {
			/* do not allow '/', '\' and '<' (Javascript) in the filename */
			if (strstr(filename, "/") != NULL || strstr(filename, "\\") != NULL
			/* check for HTML < == %3c == %3C to catch javascript */
			|| strstr(filename, "<") != NULL || strstr(filename, "%3c") != NULL || strstr(filename, "%3C") != NULL) {
				fprintf(stderr, "requested PCAP filename unsafe (contained '/' or '\\')\n");
				cwd_print(fd_snd, "request rejected!");
				free(filename);
				return;
			}
			
			/* before we open the pcap file, get potential filter content */
			{
				char *tmp_val;
				
				filter.ip4 = filter.icmp4 = filter.ip6 = filter.icmp6 = filter.tcp = filter.udp = filter.dns = filter.others = 1;
				filter.limit = MODPCAP_FILTER_LIMIT_MAX;
				
				if ((tmp_val = cwd_get_value_from_var(query_string, "ip4"))) {
					if (tmp_val[0] == '1') {
						filter.ip4 = 1;
					} else {
						filter.ip4 = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "icmp4"))) {
					if (tmp_val[0] == '1') {
						filter.icmp4 = 1;
					} else {
						filter.icmp4 = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "ip6"))) {
					if (tmp_val[0] == '1') {
						filter.ip6 = 1;
					} else {
						filter.ip6 = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "icmp6"))) {
					if (tmp_val[0] == '1') {
						filter.icmp6 = 1;
					} else {
						filter.icmp6 = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "tcp"))) {
					if (tmp_val[0] == '1') {
						filter.tcp = 1;
					} else {
						filter.tcp = 0;
					}
					free(tmp_val);
				} 
				if ((tmp_val = cwd_get_value_from_var(query_string, "udp"))) {
					if (tmp_val[0] == '1') {
						filter.udp = 1;
					} else {
						filter.udp = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "dns"))) {
					if (tmp_val[0] == '1') {
						filter.dns = 1;
					} else {
						filter.dns = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "others"))) {
					if (tmp_val[0] == '1') {
						filter.others = 1;
					} else {
						filter.others = 0;
					}
					free(tmp_val);
				}
				if ((tmp_val = cwd_get_value_from_var(query_string, "limit"))) {
					filter.limit = atoi(tmp_val);
					if (filter.limit <= 0) {
						filter.limit = MODPCAP_FILTER_LIMIT_MAX; /* set to max. value */
						fprintf(stderr,
							"invalid 'limit' value (%i) from client's URL parameter.\n",
							filter.limit);
					}
					free(tmp_val);
				}
			}
			
			if (print_pcap_contents(fd_snd, filename, filter) != 0) {
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

