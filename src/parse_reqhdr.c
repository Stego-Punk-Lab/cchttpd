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

#include "main.h"
#include "cdpstrings.h"

#define QUESTION(_ptr, _cmd, _len)	strncmp(_ptr, _cmd, _len) == 0

#define CHECK_HDRLINE(var, str)				\
	if (!var) {					\
		var = CDP_return_linevalue(rbuf, str);	\
		if (var)				\
			break;				\
	}

char *get_nxt_word(char *);

/* return the next string until \r \n \ and \t comes */
char *
get_nxt_word(char *buf)
{
	char *ret;
	int i;
	int len;
	
	len = strlen(buf);
	for (i = 0; i < len && buf[i] != '\r' && buf[i] != '\n' && buf[i] != ' ' && buf[i] != '\t'; i++)
		;
	ret = (char *) calloc(i + 1, sizeof(char));
	if (!ret) {
		logstr(__FILE__, __LINE__, "calloc() error");
		return NULL;
	}
	strncpy(ret, buf, i);
	return ret;
}

/* parse the char buffer and place the content in a httphdr_t struct */
httphdr_t *
parse_reqhdr(char *rbuf)
{
	httphdr_t *hdr;
	char *tmp_c;
	int len;
	int i;
	
	hdr = (httphdr_t *) calloc(1, sizeof(httphdr_t));
	if (!hdr) {
		logstr(__FILE__, __LINE__, "calloc() error");
		return NULL;
	}
	
	hdr->type = HTTP_REQUEST;
	
	/* get the request method */
	if (QUESTION(rbuf, "HEAD ", 5)) {
		hdr->method = HTTP_METHOD_HEAD;
		rbuf += 5;
	} else if (QUESTION(rbuf, "GET ", 4)) {
		hdr->method = HTTP_METHOD_GET;
		rbuf += 4;
	} else if (QUESTION(rbuf, "POST ", 5)) {
		hdr->method = HTTP_METHOD_POST;
		rbuf += 5;
	} else if (QUESTION(rbuf, "PUT ", 4)) {		/* not implemented */
		hdr->method = HTTP_METHOD_PUT;
		rbuf += 4;
		hdr->error = 1;
		return hdr;
	} else if (QUESTION(rbuf, "DELETE ", 7)) {	/* not implemented */
		hdr->method = HTTP_METHOD_DELETE;
		rbuf += 7;
		hdr->error = 1;
		return hdr;
	} else if (QUESTION(rbuf, "TRACE ", 6)) {	/* not implemented */
		hdr->method = HTTP_METHOD_TRACE;
		rbuf += 6;
		hdr->error = 1;		
		return hdr;
	} else if (QUESTION(rbuf, "OPTIONS ", 8)) {
		hdr->method = HTTP_METHOD_OPTIONS;
		rbuf += 8;
	} else if (QUESTION(rbuf, "CONNECT ", 8)) {	/* not implemented */
		hdr->method = HTTP_METHOD_CONNECT;
		rbuf += 8;
		hdr->error = 1;
		return hdr;
	} else {
		hdr->method = HTTP_METHOD_UNKNOWN;
		hdr->error = 1;
		return hdr;
	}
#ifdef DEBUG
	printf("METHOD: 0x%x\n", hdr->method);
#endif
	/* get the URI */
	hdr->uri = get_nxt_word(rbuf);
#ifdef DEBUG
	printf("URI: %s\n", hdr->uri);
#endif
	if (!hdr->uri || hdr->uri[0] == '\0') {
		hdr->error = 1;
		return hdr;
	}
	
	/* get the HTTP version */
	rbuf += strlen(hdr->uri) + 1;
	if (QUESTION(rbuf, "HTTP/1.1", 8)) {
		hdr->httpver = HTTP_1_1;
	} else if (QUESTION(rbuf, "HTTP/1.0", 8)) {
		/* I don't think that I will implement HTTP/1.0 completely and will disable it here soon */
		hdr->httpver = HTTP_1_0;
	} else {
		hdr->httpver = HTTP_UNSUPPORTED_VER;
		return hdr;
	}
	rbuf += 10 /* "HTTP/x.y\r\n" */;
#ifdef DEBUG
	printf("VERSION: 0x%x\n", hdr->httpver);
#endif

	/* Now parse line-wise */
	while (rbuf[0] != '\0' && rbuf[0] != '\r') {
//		putchar('%');fflush(stdout);
		switch(rbuf[0]) {
		case 'a':
		case 'A':
			CHECK_HDRLINE(hdr->cs.cli.accept, "ACCEPT:")
			break;
		case 'c':
		case 'C':
			CHECK_HDRLINE(hdr->cache_control, "CACHE-CONTROL:")
			
			if (hdr->connection == 0) {
				tmp_c = CDP_return_linevalue(rbuf, "CONNECTION:");
				/* try to find 'close' */
				if (tmp_c) {
					len = strlen(tmp_c); /* close needs at least 5 chars space */
		
					for (i = 0; !hdr->connection && i < (len - 4); i++) {
						if ( (tmp_c[i] == 'c' || tmp_c[i] == 'C')
						  && (tmp_c[i+1] == 'l' || tmp_c[i+1] == 'L')
						  && (tmp_c[i+2] == 'o' || tmp_c[i+2] == 'O')
						  && (tmp_c[i+3] == 's' || tmp_c[i+3] == 'S')
						  && (tmp_c[i+4] == 'e' || tmp_c[i+4] == 'E')
						)
							hdr->connection = CONNECTION_CLOSE;
					}

					// Don't search for it since we auto-keep-alive a connection if
					// no 'close' was sent! /* try to find keep-alive */
					//if (!hdr->connection) {
					//	//len -= 4; /* keep alive needs even more space */
					//	for (i = 0; i < len && hdr->connection ^ CONNECTION_KEEPALIVE; i++) {
					//		if (tmp_c[i] == 'k' || tmp_c[i] == 'K')
					//			if (strcasecmp(tmp_c + i + 1, "eep-alive") == 0) {
					//				hdr->connection = CONNECTION_KEEPALIVE;
					//			}
					//	}
					//}
	
					/* Todo: Maybe check for Connection: ...TE... (but I possibly can
					 * handle TE by only searching for the TE-field ... */
					free(tmp_c);
					break;
				}
			}
			break;
		case 'd':
		case 'D':
			CHECK_HDRLINE(hdr->date, "DATE:")
			break;
		case 'h':
		case 'H':
			CHECK_HDRLINE(hdr->cs.cli.host, "HOST:")
			break;
		case 't':
		case 'T':
			CHECK_HDRLINE(hdr->cs.cli.te, "TE:")
			break;
		case 'u':
		case 'U':
			CHECK_HDRLINE(hdr->cs.cli.usage_agent, "USER-AGENT:")
			break;
		default:
			
			/* TODO: das muss noch alles groß geschrieben werden !!! */
		/*	hdr->pragma = CDP_return_linevalue(rbuf, "Pragma:");
			hdr->trailer = CDP_return_linevalue(rbuf, "Trailer:");
			hdr->transfer_encoding = CDP_return_linevalue(rbuf, "Transfer-Encoding:");
			hdr->upgrade = CDP_return_linevalue(rbuf, "Upgrade:");
			hdr->via = CDP_return_linevalue(rbuf, "Via:");
			hdr->warning = CDP_return_linevalue(rbuf, "Warning");
		*/	
			/*hdr->cs.cli.accept_charset = CDP_return_linevalue(rbuf, "Accept-Charset:");
			hdr->cs.cli.accept_encoding = CDP_return_linevalue(rbuf, "Accept-Encoding:");
			hdr->cs.cli.accept_language = CDP_return_linevalue(rbuf, "Accept-Language:");
			hdr->cs.cli.authorization = CDP_return_linevalue(rbuf, "Authorization:");
			hdr->cs.cli.cookie = CDP_return_linevalue(rbuf, "Cookie:");
			hdr->cs.cli.expect = CDP_return_linevalue(rbuf, "Expect:");
			hdr->cs.cli.from = CDP_return_linevalue(rbuf, "From:");*/
		/*	hdr->cs.cli.if_modified_since = CDP_return_linevalue(rbuf, "If-Modified-Since:");
			hdr->cs.cli.if_match = CDP_return_linevalue(rbuf, "If-Match:");
			hdr->cs.cli.if_none_match = CDP_return_linevalue(rbuf, "If-None-Match:");
			hdr->cs.cli.if_range = CDP_return_linevalue(rbuf, "If-Range:");
			hdr->cs.cli.if_unmodified_since = CDP_return_linevalue(rbuf, "If-Unmodified-Since:");
			hdr->cs.cli.max_forwards = CDP_return_linevalue(rbuf, "Max-Forwards:");
			hdr->cs.cli.proxy_authorization = CDP_return_linevalue(rbuf, "Proxy-Authorization:");
			hdr->cs.cli.range = CDP_return_linevalue(rbuf, "Range:");
			hdr->cs.cli.referer = CDP_return_linevalue(rbuf, "Referer:");*/
			/* 'Allow:' is only used by PUT-Request (currently not implemented) and by
			 * Server RESPONSES.
			 tmp_c = CDP_return_linevalue(rbuf, "Allow:");
			 if (tmp_c) {
				 // now parse tmp_c and set hdr->allow
				 hdr->allow ...;
			 }*/
		/*	hdr->content_encoding = CDP_return_linevalue(rbuf, "Content-Encoding:");
			hdr->content_language = CDP_return_linevalue(rbuf, "Content-Language:");
			hdr->content_length = CDP_return_linevalue(rbuf, "Content-Length:");
			hdr->content_location = CDP_return_linevalue(rbuf, "Content-Location:");
			hdr->content_md5 = CDP_return_linevalue(rbuf, "Content-MD5:");
			hdr->content_range = CDP_return_linevalue(rbuf, "Content-Range:");
			hdr->content_type = CDP_return_linevalue(rbuf, "Content-Type:");
			hdr->expires = CDP_return_linevalue(rbuf, "Expires:");
			hdr->last_modified = CDP_return_linevalue(rbuf, "Last-Modified:");*/
			break;
		}
		/* go the the start of the next line */
		for (i = 0; rbuf[i] != '\r' && rbuf[i] != '\0'; i++)
			;
		rbuf += i;
		
		if (rbuf[0] == '\r' && rbuf[1] == '\n')
			rbuf += 2;
	}
	
	/* if there was NO connection close/keep-alive, we will keep it (for performance reasons) it! */
	if (!(hdr->connection/*^CONNECTION_TE*/))
		hdr->connection |= CONNECTION_KEEPALIVE;
		
#ifdef DEBUG
	printf("hdr->connection: 0x%x\n", hdr->connection);
#endif
	return hdr;
}


