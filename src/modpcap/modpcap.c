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

	switch(datalink){
	case DLT_NULL:
		framelen=0;
		break;
	case DLT_LOOP:
		framelen=4;
		break;
	case DLT_EN10MB:
		framelen=sizeof(struct ether_header);
		break;
	case DLT_IEEE802:
		framelen = 22;
		break;
	case DLT_LINUX_SLL:
		framelen = 16;
		break;
	case DLT_SLIP:
		framelen=24;
		break;
	case DLT_PPP:
		framelen=24;
		break;
	case DLT_FDDI:
		framelen=2+1+1+6+6;	/* 16; not tested! */
		break;
#ifdef DLT_IEEE802_11		/* OpenBSD >= 3.4 */
	case DLT_IEEE802_11:
#else	/* ifdef DLT_IEEE802 */	/* OpenBSD <= 3.3 -- I wrote this code in 2008 :) */
	case DLT_IEEE802:
#endif
		framelen=2+2+6+6+6+2+6;	/* 30; not tested! */
		break;
	case DLT_ENC:		/* Todo: IPSec */
	default:
		fprintf(stderr, "datalink type %i not supported.\n", datalink);
		return 0;
	}
#ifdef DEBUG
	printf("pcap.framelen=%i\n", framelen);
#endif
	return framelen;
}

char *
push(int *realloc_len, char *output, char *string_to_add)
{
	int add_len = strlen(string_to_add);

	if (output == NULL) {
		fprintf(stderr, "output==NULL in push()\n");
		return NULL;
	}

	if (!(output = realloc(output, *realloc_len + add_len + 1))) {
		return NULL;
	}
	bzero(output + *realloc_len, add_len + 1);
	memcpy(output + *realloc_len, string_to_add, add_len);
	*realloc_len += add_len;
	return output;
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
}

void
handle_udp(_udphdr *udphdr, _hdr_descr *hdr_desc)
{
	snprintf(hdr_desc->str_udp_sport, sizeof(hdr_desc->str_udp_sport) - 1, "%u", htons(udphdr->uh_sport));
	snprintf(hdr_desc->str_udp_dport, sizeof(hdr_desc->str_udp_dport) - 1, "%u", htons(udphdr->uh_dport));
	snprintf(hdr_desc->str_udp_len, sizeof(hdr_desc->str_udp_len) - 1, "%u", htons(udphdr->uh_ulen));
	snprintf(hdr_desc->str_udp_cksum, sizeof(hdr_desc->str_udp_cksum) - 1, "%u", htons(udphdr->uh_sum));
}

char *
print_pcap_contents(char *filename)
{
	pcap_t         *descr;
	const u_char   *packet;
	struct pcap_pkthdr hdr;
	_iphdr         *iphdr;
	_ip6hdr        *ip6hdr;
	_tcphdr        *tcphdr;
	_udphdr	       *udphdr;
	int             datalink;
	int             framelen;
	int             count = 0;
	struct ether_header *eh;
	char errbuf[PCAP_ERRBUF_SIZE];
	char            header[] = {
		"num.packets=_________________\n"
		"timestamp;caplen;wirelen;ethertype;l3prot;"
		"ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.sum_raw;"
		"ip6.src;ip6.dst;"
		"tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;"
		"udp.sport;udp.dport;udp.len;udp.cksum\n"
	   };
	char            *output = NULL;
	int realloc_len = 0;
	_hdr_descr hdr_desc;
	char new_pkt_str[4096] = { '\0' };
	char *filename_full_path = NULL;
	
	if ((filename_full_path = calloc(sizeof(char), strlen(PCAP_BASEPATH) + strlen(filename) + 1)) == NULL) {
		perror("calloc");
		fprintf(stderr, "calloc()");
		return NULL;
	}
	memcpy(filename_full_path, PCAP_BASEPATH, strlen(PCAP_BASEPATH));
	memcpy(filename_full_path+strlen(PCAP_BASEPATH), filename, strlen(filename));

	if ((descr = pcap_open_offline(filename_full_path, errbuf)) == NULL) {
#ifdef DEBUG
		fprintf(stderr, "pcap file: %s\n", filename_full_path);
#endif
		free(filename_full_path);
		perror("pcap_open_offline()");
		return NULL;
	}
	free(filename_full_path);

	datalink = pcap_datalink(descr);
	if ((framelen = get_framelen(datalink)) == 0) {
		fprintf(stderr, "invalid frame length\n");
		return NULL;
	}

	realloc_len = strlen(header);
	if (!(output = calloc(realloc_len + 1, sizeof(char)))) {
		perror("calloc");
		return NULL;
	}
	memcpy(output, header, realloc_len);

	while ((packet = pcap_next(descr, &hdr)) != NULL) {
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
		if (hdr.caplen < sizeof(struct ether_header)) {
			fprintf(stderr, "Packet too small for Ethernet header. Skipping.\n");
			break;
		}
		eh = (struct ether_header *) packet;

		switch (htons(eh->ether_type)) {
		case ETHERTYPE_IP:
			// check if iphdr fits into rest of frame b/f cont.
			if (hdr.caplen < (sizeof(struct ether_header) + sizeof(_iphdr))) {
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
				hdr_desc.str_l3_proto = "icmp";
				break;
			case 2:
				hdr_desc.str_l3_proto = "igmp";
				break;
			case 6:
				hdr_desc.str_l3_proto = "tcp";
				tcphdr = (_tcphdr *) (packet + framelen + (iphdr->ip_hl*4));
				//FIXME: check pkt len to see if it fits tcphdr
				handle_tcp(tcphdr, &hdr_desc);
				break;
			case 17:
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
			if (hdr.caplen < (sizeof(struct ether_header) + sizeof(_ip6hdr))) {
				fprintf(stderr, "Packet too small for IP6 header. Skipping.\n");
				break;
			}
			ip6hdr = (_ip6hdr *) (packet + framelen);
			hdr_desc.str_ether_type = "ip6";
			/* convert IPv6 addrs into str */
			if (inet_ntop(AF_INET6, &ip6hdr->ip6_src, hdr_desc.str_ip6_src, sizeof(hdr_desc.str_ip6_src)) == NULL) {
				perror("inet_ntop()");
				return NULL;
			}
			if (inet_ntop(AF_INET6, &ip6hdr->ip6_dst, hdr_desc.str_ip6_dst, sizeof(hdr_desc.str_ip6_dst)) == NULL) {
				perror("inet_ntop()");
				return NULL;
			}
			switch (ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
			case 1:
				hdr_desc.str_l3_proto = "icmp";
				break;
			case 2:
				hdr_desc.str_l3_proto = "igmp";
				break;
			case 6:
				hdr_desc.str_l3_proto = "tcp";
				//FIXME: check pkt len to see if it fits tcphdr
				tcphdr = (_tcphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_tcp(tcphdr, &hdr_desc);
				break;
			case 17:
				hdr_desc.str_l3_proto = "udp";
				//FIXME: check pkt len to see if it fits udphdr
				udphdr = (_udphdr *) (packet + framelen + sizeof(_ip6hdr));
				handle_udp(udphdr, &hdr_desc);
				break;
			case 58:
				hdr_desc.str_l3_proto = "icmp6";
				break;
			case 59:
				hdr_desc.str_l3_proto = ""; /* IPv6-NoNxt */
				break;
			case 60:
				hdr_desc.str_l3_proto = "ip6-dst-opts";
				break;
			default:
				/* other protocol: TODO: use numeric value */
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
		snprintf(new_pkt_str, sizeof(new_pkt_str) - 1,
			"%ld.%06ld;%u;%u;" /* meta+frame */
			"%s;%s;" /* l2 and l3 protos */
			"%s;%s;%s;%s;%s;%s;%s;%s;%s;" /* ip4 */
			"%s;%s;" /* ip6 */
			"%s;%s;%s;%s;%s;%s;%s;%s;" /* tcp */
			"%s;%s;%s;%s" /* udp */
			"\n",
			/* meta + frame */
			hdr.ts.tv_sec, hdr.ts.tv_usec, hdr.caplen, hdr.len,
			/* ethernet and proto types */
		    	hdr_desc.str_ether_type, (hdr_desc.str_l3_proto == NULL ? "" : hdr_desc.str_l3_proto),
		    	/* ipv4 */
			(iphdr != NULL ? inet_ntoa(iphdr->ip_src) : ""), (iphdr != NULL ? inet_ntoa(iphdr->ip_dst) : ""), hdr_desc.str_ip_v, hdr_desc.str_ip_hl, hdr_desc.str_ip_tos, hdr_desc.str_ip_id, hdr_desc.str_ip_off, hdr_desc.str_ip_ttl, hdr_desc.str_ip_sum,
			/* ipv6 */
			hdr_desc.str_ip6_src, hdr_desc.str_ip6_dst,
			/* tcp */
		    	hdr_desc.str_tcp_sport, hdr_desc.str_tcp_dport, hdr_desc.str_tcp_seq, hdr_desc.str_tcp_ack, hdr_desc.str_tcp_off, hdr_desc.str_tcp_flags, hdr_desc.str_tcp_win, hdr_desc.str_tcp_urp,
		    	/* udp */
			hdr_desc.str_udp_sport, hdr_desc.str_udp_dport, hdr_desc.str_udp_len, hdr_desc.str_udp_cksum);
		
		output = push(&realloc_len, output, new_pkt_str);
	}
	/* now put the packet count at the beginning of the string */
	snprintf(output, 29, "num.packets=%.16d", count);
	output[28]='\n';
	/*fprintf(stderr, "returning output ... %s\n", output);*/
	return output;
}



// /home/wendzel/git/VL_NetSec/uebungen/2021/Blatt1/capture.pcap
// /home/wendzel/git/papers/002_Unfinished/TDSC_DYST/recordings/CS_home_idle_saturday_away.pcap
// /home/wendzel/git/projects/old_projects/xyriahttpd/ip6.pcap

void mod_reqhandler(_cwd_hndl hndl, char *query_string)
{
	char *pcap_output = NULL;
	if (query_string) {
		char *filename;
		filename = cwd_get_value_from_var(query_string, "file");
		if (filename) {
			/* FIXME: filename allows for a javascript injection! */
			// (TODO)
			
			/* do not allow '/' in the filename */
			if (strstr(filename, "/") != NULL || strstr(filename, "\\") != NULL) {
				fprintf(stderr, "requested PCAP filename unsafe (contained / or \\)\n");
				cwd_print(hndl, "request rejected!");
				free(filename);
				return;
			}
			pcap_output = print_pcap_contents(filename);
			if (pcap_output) {
#ifdef DEBUG
				printf("len of pcap.output: %li\n", strlen(pcap_output));
#endif
				cwd_print(hndl, pcap_output);
				free(pcap_output);
			} else {
				cwd_print(hndl, ERROR_PCAP_FILE_NOT_OPENED);
			}
		} else {
			cwd_print(hndl, ERROR_PCAP_FILEQUERY_MISSING);
		}
		free(filename);	
	} else {
		cwd_print(hndl, ERROR_PCAP_FILEQUERY_MISSING);
	}
}

