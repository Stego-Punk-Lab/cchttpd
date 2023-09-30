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
#include <limits.h>
#include <fcntl.h>

void free_hdr_contents(httphdr_t, u_int8_t);
static void kill_connection(server_cb_inf *);
int send_filebody(int, int, size_t);

#define MAKE_FREE(__x__)	if (__x__ != NULL) { free(__x__); __x__ = NULL; }

void
free_hdr_contents(httphdr_t hdr, u_int8_t type)
{
	/* free structure components) */
	MAKE_FREE(hdr.uri)
	MAKE_FREE(hdr.abs_path)
	MAKE_FREE(hdr.path)
	MAKE_FREE(hdr.cache_control)
	MAKE_FREE(hdr.date)
	MAKE_FREE(hdr.pragma)
	MAKE_FREE(hdr.trailer)
	MAKE_FREE(hdr.transfer_encoding)
	MAKE_FREE(hdr.upgrade)
	MAKE_FREE(hdr.via)
	MAKE_FREE(hdr.warning)
	if (type == TYPE_CLIENT) {
		MAKE_FREE(hdr.cs.cli.accept)
		MAKE_FREE(hdr.cs.cli.accept_charset)
		MAKE_FREE(hdr.cs.cli.accept_encoding)
		MAKE_FREE(hdr.cs.cli.accept_language)
		MAKE_FREE(hdr.cs.cli.authorization)
		MAKE_FREE(hdr.cs.cli.cookie)
		MAKE_FREE(hdr.cs.cli.expect)
		MAKE_FREE(hdr.cs.cli.from)
		MAKE_FREE(hdr.cs.cli.host)
		MAKE_FREE(hdr.cs.cli.if_modified_since)
		MAKE_FREE(hdr.cs.cli.if_match)
		MAKE_FREE(hdr.cs.cli.if_none_match)
		MAKE_FREE(hdr.cs.cli.if_range)
		MAKE_FREE(hdr.cs.cli.if_unmodified_since)
		MAKE_FREE(hdr.cs.cli.max_forwards)
		MAKE_FREE(hdr.cs.cli.proxy_authorization)
		MAKE_FREE(hdr.cs.cli.range)
		MAKE_FREE(hdr.cs.cli.referer)
		MAKE_FREE(hdr.cs.cli.te)
		MAKE_FREE(hdr.cs.cli.usage_agent)
	} else if (type == TYPE_SERVER) {
		MAKE_FREE(hdr.cs.srv.accept_ranges)
		MAKE_FREE(hdr.cs.srv.age)
		MAKE_FREE(hdr.cs.srv.etag)
		MAKE_FREE(hdr.cs.srv.location)
		MAKE_FREE(hdr.cs.srv.proxy_authenticate)
		MAKE_FREE(hdr.cs.srv.retry_after)
		MAKE_FREE(hdr.cs.srv.server)
		MAKE_FREE(hdr.cs.srv.set_cookie)
		MAKE_FREE(hdr.cs.srv.vary)
		MAKE_FREE(hdr.cs.srv.www_authenticate)
	}
	MAKE_FREE(hdr.content_encoding)
	MAKE_FREE(hdr.content_language)
	MAKE_FREE(hdr.content_length)
	MAKE_FREE(hdr.content_location)
	MAKE_FREE(hdr.content_md5)
	MAKE_FREE(hdr.content_range)
	/* don't free content_type since it points to static mem!
	 * this will maybe change after I implemented it really with MIME or whatever shit it needs...
	 * MAKE_FREE(hdr.content_type) */
	MAKE_FREE(hdr.expires)
	MAKE_FREE(hdr.last_modified)
	MAKE_FREE(hdr.body)
}

/* send the content of a file, e.g., a GET-requested /index.html, an error page or a tmp output of a C module */
int
send_filebody(int sockfd, int filefd, size_t numbytes)
{
#ifndef __linux__
	ssize_t read_cur = 0;
	size_t read_left = -1;
	size_t read_next = 0; /* how many bytes to read next */
	char *buf = NULL;

	if (!(buf = (char *) calloc(FILE_READING_CHUNKSIZE + 1, sizeof(char))))
		return RET_ERR;

	read_left = numbytes;

	if (numbytes >= 0xffffffff) {
		fprintf(stderr, "Requested file is TOO BIG (%zu bytes)!\n", numbytes);
		return RET_ERR;
	} else {
		while (read_left) {
			read_next = ( read_left > FILE_READING_CHUNKSIZE ? FILE_READING_CHUNKSIZE : read_left );
			if ((read_cur = read(filefd, buf, read_next)) == -1) {
				perror("read()");
				logstr(__FILE__, __LINE__, "read() error");
				return RET_ERR;
			} else {
				read_left -= read_cur;
				if (write(sockfd, buf, read_cur) == -1) {
					perror("write()");
					logstr(__FILE__, __LINE__, "write() error");
					return RET_ERR;
				}
			}
		}
	}
#else /* use Linux' sendfile() */
	if (sendfile(sockfd, filefd, NULL, numbytes) == -1) {
		perror("sendfile()");
		logstr(__FILE__, __LINE__, "sendfile() error");
		return RET_ERR;
	}
#endif
	return RET_OK;
}

void
do_server(void *sock_info_p)
{
	char rbuf[MAX_REQHDR_LEN + 1] = { '\0' };
	int len = 0;
	sinf_t *sinf;
	server_cb_inf inf;
	int found;
	int i;
	int num_recv_bytes_from_client;
	char *sbuf;
	int error;
	int file;
	httphdr_t shdr;
	fd_set fds;
	int yup = 1, nope = 0;
	const struct timespec tv = {7, 0}; /* connection timeout */
	uint8_t go_on = 1;
	sinf = (sinf_t *) sock_info_p; /* This is _SOCK_-inf */
	inf.sinf = sinf; /* this is 'inf' containing everything */

	FD_ZERO(&fds);
	bzero(&shdr, sizeof(httphdr_t));
	
	while (go_on) {
		found = 0;
		
		FD_SET(sinf->fd, &fds);
		if (pselect(sinf->fd + 1, &fds, NULL, NULL, &tv, NULL) == -1) {
			logstr(__FILE__, __LINE__, "select returned with an error.");
			kill_connection(&inf);
			go_on = 0;
		}
	
		/* if max. len of hdr data we can still request is zero (or error occured) ...
		 * OR: if the select timeout was reached and there still is no data: kill connection. */
		if ((num_recv_bytes_from_client = recv(sinf->fd, rbuf + len, MAX_REQHDR_LEN - len, MSG_DONTWAIT)) <= 0) {
			/* kill connection if the client sends more bytes than allowed */
			kill_connection(&inf);
			go_on = 0;
		}
		len += num_recv_bytes_from_client;
		
		/* did we already receive '\r\n\r\n'? I think parsing from the end of the string
		 * to its beginning should be the most performant solution since there is no HTTP
		 * message body sent with most of the requests. */
		for (i = len - 1; !found && i >= 3; i--) {
			/* note: this works reverse */
			if (rbuf[i-3] == '\r' && rbuf[i-2] == '\n' && rbuf[i-1] == '\r' && rbuf[i] == '\n')
				found = 1; /* break */
		}
		if (found) { /* now proceed */
#ifdef DEBUG
			printf("string from client '%s'\n", rbuf);
#endif
			/* Ignore trailing CRLF to be conform w/ RFC 2616 */
			for (i = 0; rbuf[i] == '\r' && rbuf[i+1] == '\n'; i += 2)
				;
			/* get the HTTP request header in a struct */
			inf.hdr = parse_reqhdr(rbuf + i);
			error = create_respinf(inf.hdr, &shdr);
			sbuf = create_respbuf(&shdr, error);
			if (sbuf) {
#ifdef DEBUG
				printf("RESPONSE='%s'\n", sbuf);
#endif
#ifdef TCP_CORK
				setsockopt(sinf->fd, IPPROTO_TCP, TCP_CORK, &yup, sizeof(yup));
#endif
				if (write(sinf->fd, sbuf, strlen(sbuf)) == -1) {
					perror("write");
					logstr(__FILE__, __LINE__, "write() error");
				}
				free(sbuf);
				sbuf = NULL;
			} else {
				fprintf(stderr, "Empty response buffer.\n");
				logstr(__FILE__, __LINE__, "Empty response buffer");
				kill_connection(&inf);
				go_on = 0;
				/* try continuing */
			}
			if (inf.hdr->method == HTTP_METHOD_HEAD) {
				/* just do the clean-up */
				unlink(shdr.cgi_tmpfile_name);
			}
			/* if there was no/an error and an GET request (and NO c-module): send the file. */
			//FIXME: above comment mentions c-module but below, C-module is handled!
			else if ((inf.hdr->method == HTTP_METHOD_GET || error) &&
					/* no error -or- error-page is needed! */
					(error == 0 || error == ERROR_FORBIDDEN
						    || error == ERROR_404
						    || error == ERROR_METHOD_NOT_ALLOWED
						    || error == ERROR_UNDEFINED)
			) {
				/* if this is a real file, open it first, if this is pipe input from cgi/c-module, use
				 * it directly */
				if (shdr.is_cmod) {
					if (send_filebody(sinf->fd, shdr.cgi_file, shdr.filesize) == RET_ERR) {
						logstr(__FILE__, __LINE__, "send_filebody() returned w/ error");
						kill_connection(&inf);
						go_on = 0;
					}
					close(shdr.cgi_file);
					/* remove tmp file */
					unlink(shdr.cgi_tmpfile_name);
				} else {
					if ((file = open(shdr.abs_path, O_RDONLY)) == -1) {
						logstr(__FILE__, __LINE__, "unable to open a requested file");
#ifdef DEBUG
						/* this could be a formatstring attack and is thus only used in DEBUG mode */
						logstr(__FILE__, __LINE__, shdr.abs_path);
#endif
						kill_connection(&inf);
						go_on = 0;
					} else {
						if (send_filebody(sinf->fd, file, shdr.filesize) == RET_ERR) {
							logstr(__FILE__, __LINE__, "send_filebody() returned w/ error");
							kill_connection(&inf);
							go_on = 0;
						}
						close(file);
					}
				}
			}
#ifdef TCP_CORK
			setsockopt(sinf->fd, IPPROTO_TCP, TCP_CORK, &nope, sizeof(nope));
#endif
			free_hdr_contents(shdr, TYPE_SERVER);
			/* if there was an error or a explicit close ... */
			if (shdr.connection & CONNECTION_CLOSE || error) {
				//bzero(&shdr, sizeof(httphdr_t));
				kill_connection(&inf);
				go_on = 0;
			}
			bzero(&shdr, sizeof(httphdr_t));
			bzero(rbuf, len);
			len = 0;
		}
	}
}

static void
kill_connection(server_cb_inf *inf)
{
	/* to save a LITTLE bit performance: decrement # connections before we really
	 * shut the connection down. this sould make no problems.
	 */
//	if (pthread_mutex_lock(&mutex_numconnects) != 0) {
//		logstr(__FILE__, __LINE__, "unable to do pthread_mutex_lock()\n");
//	}
//	num_connections--;
//	if (pthread_mutex_unlock(&mutex_numconnects) != 0) {
//		logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
//	}
	close(inf->sinf->fd);
	
#ifdef DEBUG
	printf("server closed connection to client.\n");
#endif
	//free(inf);
	//pthread_detach(pthread_self());
	//pthread_exit(NULL);
}


