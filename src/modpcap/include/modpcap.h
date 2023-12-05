/*
 * ccHTTPd is distributed under the following license:
 *
 * Copyright (c) 2023 Steffen Wendzel <steffen (at) wendzel (dot) de> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must display the following acknowledgement: This product includes software developed by the <copyright holder>.
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */
/* THIS FILE IS BASED ON CONTENT OF OpenBSD's sys/netinet/ip.h, WHICH HAS THE FOLLOWING COPYRIGHT STATEMENT: */
/*	$OpenBSD: ip.h,v 1.20 2021/12/14 23:47:36 dtucker Exp $	*/
/*	$NetBSD: ip.h,v 1.9 1995/05/15 01:22:44 cgd Exp $	*/
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip.h	8.1 (Berkeley) 6/10/93
 */
/* FURTHER CONTENT on TCP and UDP ARE BASED ON OpenBSD's tcp.h and udp.h: */
/*	$OpenBSD: tcp.h,v 1.24 2023/05/19 01:04:39 guenther Exp $	*/
/*	$NetBSD: tcp.h,v 1.8 1995/04/17 05:32:58 cgd Exp $	*/

/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)tcp.h	8.1 (Berkeley) 6/10/93
 */
/*	$OpenBSD: udp.h,v 1.5 2003/06/02 23:28:15 millert Exp $	*/
/*	$NetBSD: udp.h,v 1.6 1995/04/13 06:37:10 cgd Exp $	*/
/*
 * Copyright (c) 1982, 1986, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)udp.h	8.1 (Berkeley) 6/10/93
 */
/* More content is based on OpenBSD's arpa/namserv.h which has the following
 * copyright statement:
 *	$OpenBSD: nameser.h,v 1.15 2022/12/27 07:44:56 jmc Exp $	*/
/*
 * ++Copyright++ 1983, 1989, 1993
 * -
 * Copyright (c) 1983, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * Portions Copyright (c) 1995 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * To the extent it has a right to do so, IBM grants an immunity from suit
 * under its patents, if any, for the use, sale or manufacture of products to
 * the extent that such products are used for performing Domain Name System
 * dynamic updates in TCP/IP networks by means of the Software.  No immunity is
 * granted for any product per se or for any other function of any product.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 * --Copyright--
 */

/*
 *      @(#)nameser.h	8.1 (Berkeley) 6/2/93
 *	$From: nameser.h,v 8.11 1996/10/08 04:51:02 vixie Exp $
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/udp.h>
#ifdef __linux__
	#include <net/ethernet.h>
	#include <pcap/pcap.h>
#elif __OpenBSD__
	#include <net/if_arp.h>
	#include <netinet/if_ether.h>
	#include <pcap.h>
#endif

/* currently, we only support little endian, e.g., in DNS */
#ifdef __linux__
	#if !defined(__BYTE_ORDER__) || (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
		#error "Currently only supporting little endian systems."
	#endif
#else
	#if !defined(_BYTE_ORDER) || \
	    (_BYTE_ORDER != _BIG_ENDIAN && _BYTE_ORDER != _LITTLE_ENDIAN && \
	    _BYTE_ORDER != _PDP_ENDIAN)
		#error "Currently only supporting little endian systems."
	#endif
#endif

#ifndef PCAP_BASEPATH
	#define PCAP_BASEPATH "/var/www/pcaps/"
#endif

#define ERROR_PCAP_FILEQUERY_MISSING "<html><body>Error: You need to provide a filename in the URL. Example: <code>?file=ip6.pcap</code> (the pcap file must be located in <i>" PCAP_BASEPATH "</i>).</body></html>"
#define ERROR_PCAP_FILE_NOT_OPENED "<html><body>Error: Unable to open your requested file (probably not found or no permission, see server output).</body></html>"

#define BZERO(x) bzero(x, sizeof(x));

typedef struct {
	u_int8_t	ip4:1;
	u_int8_t	icmp4:1;
	u_int8_t	ip6:1;
	u_int8_t	icmp6:1;
	u_int8_t	udp:1;
	u_int8_t	tcp:1;
	u_int8_t	dns:1;
	u_int8_t	others:1;
	u_int8_t	none:1;
#define MODPCAP_FILTER_LIMIT_MAX	0x7fffffff
	int		limit;
} _pcap_filter;

/* Imported from OpenBSD sys/netinet/ip.h; modified for ccHTTPd */
typedef struct {
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t        ip_hl:4;
	u_int8_t        ip_v:4;
#elif BYTE_ORDER == BIG_ENDIAN
	u_int8_t        ip_v:4;
	u_int8_t        ip_hl:4;
#else
	#error BYTE_ORDER undefined!
#endif
	u_int8_t        ip_tos;
	u_int16_t       ip_len;
	u_int16_t       ip_id;
	u_int16_t       ip_off;
	u_int8_t        ip_ttl;
	u_int8_t        ip_p;
	u_int16_t       ip_sum;
	struct in_addr  ip_src;
	struct in_addr  ip_dst;
} _iphdr;

/* Imported from OpenBSD sys/netinet/ip6.h; modified for ccHTTPd */
typedef struct
{
	union {
		struct ip6_hdrctl {
			u_int32_t ip6_un1_flow;	/* 20 bits of flow-ID */
			u_int16_t ip6_un1_plen;	/* payload length */
			u_int8_t  ip6_un1_nxt;	/* next header */
			u_int8_t  ip6_un1_hlim;	/* hop limit */
		} ip6_un1;
		u_int8_t ip6_un2_vfc;	/* 4 bits version, top 4 bits class */
	} ip6_ctlun;
	struct in6_addr ip6_src;	/* source address */
	struct in6_addr ip6_dst;	/* destination address */
} _ip6hdr;

/* Imported from OpenBSD sys/netinet/tcp.h; modified for ccHTTPd */
typedef struct {
	u_int16_t       th_sport;
	u_int16_t       th_dport;
	u_int32_t       th_seq;
	u_int32_t       th_ack;
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t        th_x2:4,/* (unused) */
	                th_off:4;
#elif BYTE_ORDER == BIG_ENDIAN
	u_int8_t        th_off:4,
	th_x2:4;	/* (unused) */
#endif
	u_int8_t        th_flags;
#define	TH_FIN	  0x01
#define	TH_SYN	  0x02
#define	TH_RST	  0x04
#define	TH_PUSH	  0x08
#define	TH_ACK	  0x10
#define	TH_URG	  0x20
#define	TH_ECE	  0x40
#define	TH_CWR	  0x80
	u_int16_t       th_win;
	u_int16_t       th_sum;
	u_int16_t       th_urp;
} _tcphdr;

/* Imported from OpenBSD sys/netinet/udp.h; modified for ccHTTPd */
typedef struct
{
	u_int16_t uh_sport;		/* source port */
	u_int16_t uh_dport;		/* destination port */
	u_int16_t uh_ulen;		/* udp length */
	u_int16_t uh_sum;		/* udp checksum */
} _udphdr;


/* from OpenBSD's arpa/namserv.h; slightly modified */
typedef struct {
	unsigned	id :16;		/* query identification number */
/* Currently defined opcodes */
#define DNS_QUERY		0x0		/* standard query */
#define DNS_IQUERY		0x1		/* inverse query */
#define DNS_STATUS		0x2		/* nameserver status query */
/*#define xxx			0x3*/		/* 0x3 reserved */
#define DNS_NS_NOTIFY_OP	0x4		/* notify secondary of SOA change */
#define DNS_UPDATE		0x5
	/* fields in third byte */
	unsigned	rd :1;		/* recursion desired */
	unsigned	tc :1;		/* truncated message */
	unsigned	aa :1;		/* authoritative answer */
	unsigned	opcode :4;	/* purpose of message */
	unsigned	qr :1;		/* response flag */
	/* fields in fourth byte */
	unsigned	rcode :4;	/* response code */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/* recursion available */
	/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
} _dnshdr;

typedef struct {
	char *name;
	u_int16_t name_length;
	u_int16_t qtype;
	u_int16_t qclass;
	size_t header_offset;
} _dns_question;

// Holds the information for a dns resource record.
typedef struct { // _dns_rr {
	char *name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	// uint16_t data_len;
	uint8_t *data;
	// struct dns_rr * next;
} _dns_rr;

typedef struct
{
	/* the following pointers are used to later assemble the packet string */
	char *str_ether_type;
	char *str_l3_proto;
	
	/* the following str_*-buffers are also used to assemble the packet string */
	char /*ip4*/
		str_ip_v[3],
		str_ip_hl[3],
		str_ip_tos[4],
		str_ip_id[7],
		str_ip_off[7],
		str_ip_ttl[4],
		str_ip_p[4],
		str_ip_sum[7],
		str_ip_src[16],
		str_ip_dst[16],
	    /*ip6*/
		str_ip6_ver[3],
		str_ip6_tc[7],
		str_ip6_flow[15],
		str_ip6_plen[7],
		str_ip6_nxt[4],
		str_ip6_hlim[4],
		str_ip6_src[8*4 + 7 +1],
		str_ip6_dst[8*4 + 7 +1],
	    /*tcp*/
		str_tcp_sport[7],
		str_tcp_dport[7],
		str_tcp_seq[11],
		str_tcp_ack[11],
		str_tcp_off[3],
		str_tcp_flags[4],
		str_tcp_win[7],
		str_tcp_sum[7],
		str_tcp_urp[7],
		str_tcp_cksum[7],
	    /*udp*/
		str_udp_sport[7],
		str_udp_dport[7],
		str_udp_len[7],
		str_udp_cksum[7],
	   /* dns */
	   	str_dns_id[8],
	   	str_dns_flags[24],
	   	str_dns_opcode[3],
	   	str_dns_rcode[4],
	   	str_dns_qdcount[7],
	   	str_dns_ancount[7],
	   	str_dns_nscount[7],
	   	str_dns_arcount[7];
} _hdr_descr;


