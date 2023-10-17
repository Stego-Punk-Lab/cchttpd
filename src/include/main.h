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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <fcntl.h>

#ifdef __linux__
   #include <sys/sendfile.h>
#endif

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#ifdef __svr4__
   #include <strings.h>	
#endif
#include <netdb.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <limits.h>

#ifdef __linux__
   #include <netinet/tcp.h> /* TCP_CORK */
#endif

#include "yccw.h"

#define CCHTTPD_VER		"0.2.3"

#ifndef LOGFILE
 #define LOGFILE		"/var/log/cchttpd"
#endif
#define DEFAULT_HTDOCS		"/var/www/"
#define DEFAULT_ERRFILEDIR	"/etc/cchttpd/errfiles/"

#define MAX_REQHDR_LEN		12288 /* the max. accepted request header length */
#define FILE_READING_CHUNKSIZE	1024*1024*2 /* for reading in files during response handling */

#define RET_ERR			0x10
#define RET_OK			0x00

#define VERB_OFF		0x00
#define VERB_NRM		0x01
#define VERB_DBG		0x02

#define MAX_NUM_CONNECTIONS	0x30	/* num of acceptable connections */
#define NUM_PARA_CONNS		0x30	/* num of threads */

#define max(a, b)		(a > b ? a : b)

#define F4			1
#define F6			0
/* switch IP */
#define SWIP(i, v4, v6)		((sinf + i)->fam == AF_INET ? v4 : v6)

typedef struct {
	int fd;
	int fam;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
} sinf_t;

#define TYPE_CLIENT		0x0001
#define TYPE_SERVER		0x0002

#define ERROR_404		0x0001
#define ERROR_NOTFOUND		ERROR_404
#define ERROR_BADREQUEST	0x0002
#define ERROR_FORBIDDEN		0x0004
#define ERROR_METHOD_NOT_ALLOWED 0x0008
#define ERROR_MEMALLOC		0x4000
#define ERROR_UNDEFINED		0x8000

typedef struct {
#define HTTP_REQUEST		0x01
#define HTTP_RESPONSE		0x02
	u_int8_t type:2;
	u_int8_t error:1;	/* set to 1 if an error occured */
	u_int8_t is_cmod:1;	/* is it a successfully loaded C module? */
	int cgi_file;		/* used to read data written to the output of c-modules + cgi scripts */
	char cgi_tmpfile_name[12];
	/*u_int8_t unused:5;*/
/* Request Line */
#define HTTP_METHOD_UNKNOWN	0x00
#define HTTP_METHOD_OPTIONS	0x01
#define HTTP_METHOD_GET		0x02
#define HTTP_METHOD_HEAD	0x04
#define HTTP_METHOD_POST	0x08
#define HTTP_METHOD_PUT		0x10
#define HTTP_METHOD_DELETE	0x20
#define HTTP_METHOD_TRACE	0x40
#define HTTP_METHOD_CONNECT	0x80 /* 0x100 would need more than u_int8_t! */
	u_int8_t method;
#define HTTP_UNSUPPORTED_VER	0x01
#define HTTP_1_0		0x02
#define HTTP_1_1		0x04
	u_int8_t httpver;
	char *uri;
	char *abs_path;
	char *path;
	size_t filesize;
/* General Hdr */
	char *cache_control;
#define CONNECTION_CLOSE	0x1
#define CONNECTION_KEEPALIVE	0x2
	u_int8_t connection:4;
	char *date;
	char *pragma;
	char *trailer;
	char *transfer_encoding;
	char *upgrade;
	char *via;
	char *warning;
	union { /* client server (cs) union */
		struct {
			/* Client Request Hdr */
			char *accept;
			char *accept_charset;
			char *accept_encoding;
			char *accept_language;
			char *authorization;
			char *cookie;
			char *expect;
			char *from;
			char *host;
			char *if_modified_since;
			char *if_match;
			char *if_none_match;
			char *if_range;
			char *if_unmodified_since;
			char *max_forwards;
			char *proxy_authorization;
			char *range;
			char *referer;
			char *te;
			char *usage_agent;
		} cli;
		struct {
			/* Server Response Hdr */
			char *accept_ranges;
			char *age;
			char *etag;
			char *location;
			char *proxy_authenticate;
			char *retry_after;
			char *server;
			char *set_cookie;
			char *vary;
			char *www_authenticate;
		} srv;
	} cs;
/* Entity Hdr */
	u_int8_t allow;		/* for 405-response; must be eq to type of 'method'! */
	char *content_encoding;
	char *content_language;
	char *content_length;
	char *content_location;
	char *content_md5;
	char *content_range;	/* TODO: erstmal nicht implementieren? */
	char *content_type;
	char *expires;
	char *last_modified;
/* Message Body */
	char *body;
} httphdr_t;

typedef struct {
	sinf_t		*sinf;
	httphdr_t	*hdr;	// TODO: nutze ich das ueberhaupt???
} server_cb_inf;

typedef struct {
	sinf_t		*sinf;
	u_int8_t	is_busy:1;
	int		pipefds[2];	/* used to wait for a job */
	pthread_t	pth;
} thread_inf_t;

/* list of loaded modules. every thread can add modules. */
struct modlist {
	char *path;	/* cmp with hdr path */
/*	int handle;*/	/* auto-inc value */
	yfptrs_t *fptrs;/* function pointers */
	struct modlist *next;
};
typedef struct modlist modlist_t;

void do_server(void *);
httphdr_t *parse_reqhdr(char *);
void logstr(char *, int, char *);
void logstr1p(char *file, int line, char *str, char *para);
int create_respinf(httphdr_t *, httphdr_t *);
char *create_respbuf(httphdr_t *, int);
void free_hdr_contents(httphdr_t hdr, u_int8_t type);
char *CDP_return_linevalue(char *buf, char *key);


