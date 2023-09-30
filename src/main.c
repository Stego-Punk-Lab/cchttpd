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

/* globals */
u_int8_t verbose = 0;
u_int8_t debug = 0;
char *htdocs_path = DEFAULT_HTDOCS;
modlist_t *modlist;
//int num_connections = 0;
//pthread_mutex_t mutex_numconnects = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_cmodload = PTHREAD_MUTEX_INITIALIZER;
char ACSarray[256]={'\0'}; /* ''anti case sensitive''-array */

void usage(void);
void sig_handler(int);

void
usage()
{
	extern char *__progname;
	
	printf("usage: %s -l ip:port [ -l ip2:port ... ] | <broken:-L port>\n"
	       "      [-p alternative-htdocs-path] [-dDhvV]\n",
		__progname);
	exit(1);
}

void
sig_handler(int signr)
{
	syslog(LOG_DAEMON | LOG_NOTICE, "----clean exit after signal %i.----", signr);
	exit(1);
}


void *
thread_mainloop(void *ti_)
{
	thread_inf_t *ti;
	fd_set fds;
	char c[1];
	
	ti = (thread_inf_t *) ti_;
	
	FD_ZERO(&fds);
	
	while (1) {
		FD_SET(ti->pipefds[0], &fds);
		
		/* wait for a job */
		if (pselect(ti->pipefds[0] + 1, &fds, NULL, NULL, NULL, NULL) == -1) {
			logstr(__FILE__, __LINE__, "select returned with an error.");
			close(ti->sinf->fd);
			exit(1);
		}
		/* okay, read the useless byte */
		if (read(ti->pipefds[0], c, 1) == -1) {
			perror("read()");
			logstr(__FILE__, __LINE__, "read() returned with an error.");
			/* lets try to continue for now */
		}
		
		/* do the job */
		do_server(ti->sinf);
		
		/* inform mainloop, that we've just finished */
		ti->is_busy = 0;
	}
	/* NOTREACHED */
	return NULL;
}

int
main(int argc, char *argv[])
{
	int ch;
	int lsts = 0;
	int lsta = 0;
	int lsta_port;
	int i;
	int do_daemon = 0;
	int connfd;
	pid_t pid;
	fd_set fds;
	thread_inf_t threads[NUM_PARA_CONNS];
	socklen_t addrlen;
	int last_used_thread = 0;
	
	/* -l ip:port */
	int size = 0;
	int salen, sa6len;
	int yup = 1;
	struct sockaddr *sa_blank;
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	sinf_t *sinf = NULL;
	sinf_t *cli_sinf = NULL;
	int peak = 0;
	int port = 0;
	char *ip = NULL;
	int sinf_size = 0;
	
	int found_a_thread = 0;
	
	while ((ch = getopt(argc, argv, "dDhL:l:p:vV")) != -1) {
		switch (ch) {
		case 'd':
			verbose = debug = 1;
			break;
		case 'D':
			do_daemon = 1;
			break;
		case 'l': /* listen on a specific ip:port */
			if (lsta)
				usage();
			
			lsts = 1;
			
			/* sep. ip : port */
			for (i = strlen(optarg) - 1; i && !ip; i--) {
				if (optarg[i] == ':') {
					ip = (char *) calloc(i + 1, sizeof(char));
					if (!ip)
						err(1, "calloc");
					strncpy(ip, optarg, i);
					port = atoi(optarg + i + 1);
				}
			}
			
			if (!ip || strlen(ip) == 0) {
				fprintf(stderr, "no ip given!\n");
				exit(1);
			}
			
			if (!port || port > 0xffff || port < 1) {
				fprintf(stderr, "port missing or invalid!\n");
				exit(1);
			}
			
			if (verbose)
				printf("checking ip=%s, port=%i\n", ip, port);
			
			if (!sinf) {
				if (!(sinf = (sinf_t *) calloc(1, sizeof(sinf_t)))) {
					err(1, "calloc");
				}
			} else {
				size = sizeof(sinf_t);
				if (!(sinf = (sinf_t *) realloc(sinf, (size + 1) * sizeof(sinf_t))))
					err(1, "realloc");
			}

			bzero(&sa, sizeof(sa));
			bzero(&sa6, sizeof(sa6));
			
			if (inet_pton(AF_INET, ip, &sa.sin_addr)) {
				sa.sin_port = htons(port);
				sa.sin_family = AF_INET;
				salen = sizeof(struct sockaddr_in);
			
				if (((sinf + size)->fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
					err(1, "socket");
			
				setsockopt((sinf + size)->fd, SOL_SOCKET, SO_REUSEADDR, &yup, sizeof(yup));
			
				if (bind((sinf + size)->fd, (struct sockaddr *)&sa, salen) < 0) {
					fprintf(stderr, "%s:%i bind error\n", ip, port);
					err(1, "bind");
				}
				
				if (listen((sinf + size)->fd, MAX_NUM_CONNECTIONS) < 0)
					err(1, "listen");
				
				peak = max((sinf + size)->fd, peak);
				(sinf + size)->fam = AF_INET;
			} else if (inet_pton(AF_INET6, ip, &sa6.sin6_addr)) {
				sa6.sin6_port = htons(port);
				sa6.sin6_family = AF_INET6;
				sa6len = sizeof(struct sockaddr_in6);
			
				if (((sinf + size)->fd = socket(AF_INET6, SOCK_STREAM, 0)) < 0)
					err(1, "socket");
				
				setsockopt((sinf + size)->fd, SOL_SOCKET, SO_REUSEADDR, &yup, sizeof(yup));
				
				if (bind((sinf + size)->fd, (struct sockaddr *)&sa6, sa6len) < 0)
					err(1, "bind");
			
				if (listen((sinf + size)->fd, 5) < 0)
					err(1, "listen");
				
				peak = max((sinf + size)->fd, peak);
				(sinf + size)->fam = AF_INET6;
			} else {
				fprintf(stderr, "Invalid address: %s\n", ip);
				exit(1);
			}
			sinf_size++;
			ip = NULL; port = 0; /* reset for next iteration */
			break;
		case 'L':
			/* listen on all devices */
			fprintf(stderr, "not fully implemented. sorry.\n");
			exit(1);
			if (lsts)
				usage();
			lsta = 1;
			lsta_port = atoi(optarg);
			if (!lsta_port) {
				fprintf(stderr, "unknown -L port\n");
				usage();
				/* NOTREACHED */
			}
			break;
		case 'p':
			/* change default htdocs path */
			printf("Changing htdocs path to %s\n", optarg);
			htdocs_path = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'V':
			printf("ccHTTPd " CCHTTPD_VER "\n"
				"(C) 2008-2023 Steffen Wendzel <steffen (at) wendzel (dot) de>\n"
				"https://www.wendzel.de\n");
			return 1;
			/* NOTREACHED */
			break;
		case 'h':
		default:
			usage();
			/* NOTREACHED */
			break;
		}
	}
	
	if (!lsts && !lsta) {
		fprintf(stderr, "need -L or -l\n");
		exit(1);
	}
	
	modlist = NULL;
	
	/* 41 - 5a = upper case -> + 0x20 = lower case */
	for(i=0; i<256; i++) {
		if(i>=0x41 && i<=0x5a)
			ACSarray[i]=i+0x20;
		else
			ACSarray[i]=i;
	}

	
	FD_ZERO(&fds);
	
	/* signal handling */
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		err(1, "signal");
	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		err(1, "signal");
	
	/* start our pre-threading */
	for (i = 0; i < NUM_PARA_CONNS; i++) {
		threads[i].is_busy = 0;
		if (pipe(threads[i].pipefds) != 0)
			err(1, "pipe()");
		
		if (pthread_create(&threads[i].pth, NULL, &thread_mainloop, &threads[i]) != 0)
			err(1, "pthread_create()");
	}
	
	if (do_daemon) {
		if (debug)
			printf("creating daemon process ...");
		if ((pid = fork()) < 0)
			err(1, "fork");
		else if (pid) /* parent */
			return 0;

		setsid();
		if (chdir("/") == -1) {
			perror("chdir(\"/\"");
			exit(1);
		}
		syslog(LOG_DAEMON | LOG_NOTICE, "--- ccHTTPd started ---");
	}
	umask(077);
	
	if (verbose) {
		printf("ccHTTPd started!\n");
		printf("--- Please note this code is for scientific purposes only. It is not ready for production environments. ---\n");
	}
	
	do {
		for (i = 0; i < sinf_size; i++)
			FD_SET((sinf + i)->fd, &fds);
		
		if (select(peak + 1, &fds, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) {
				continue;
			} else {
#ifdef DEBUG
				if (errno == EFAULT) printf("EFAULT\n");
				else if (errno == EBADF) printf("EBADF\n");
				else if (errno == EINVAL) printf("EINVAL\n");
#endif
				perror("select");
				sig_handler(0);
			}
		}

		for (i = 0; i < sinf_size; i++) {
			if (FD_ISSET((sinf + i)->fd, &fds)) {
#ifdef DEBUG
				printf("Accepting TCP connection.\n");
#endif
				if ((sinf + i)->fam == AF_INET) {
					sa_blank = (struct sockaddr *) &sa;
					addrlen = salen;
				} else {
					sa_blank = (struct sockaddr *) &sa6;
					addrlen = sa6len;
				}
				
				/* if max num of connections is reached: continue */
//				if (num_connections == MAX_NUM_CONNECTIONS)
//					continue;
				
				if ((connfd = accept((sinf + i)->fd, sa_blank, &addrlen)) < 0) {
					perror("accept");
				} else {
//					if (pthread_mutex_lock(&mutex_numconnects) != 0) {
//						logstr(__FILE__, __LINE__, "unable to do pthread_mutex_lock()");
//						/* don't stop here, try to serve the request nevertheless ... */
//					}
//					num_connections++;
//					if (pthread_mutex_unlock(&mutex_numconnects) != 0) {
//						logstr(__FILE__, __LINE__, "fatal error exit: unable to do pthread_mutex_unlock()");
//						exit(1);
//					}
					
					cli_sinf = (sinf_t *) calloc(1, sizeof(sinf_t));
					if (!cli_sinf) {
						syslog(LOG_DAEMON | LOG_NOTICE, "calloc error");
						/* harakiri */
						sig_handler(0);
					}
					cli_sinf->fd = connfd;
					cli_sinf->fam = SWIP(i, F4, F6);
					memcpy(&cli_sinf->sa, &sa, sizeof(sa));
					memcpy(&cli_sinf->sa6, &sa6, sizeof(sa6));
					
					/* circular stuff */
					if (last_used_thread == (NUM_PARA_CONNS - 1))
						last_used_thread = 0;
						
					/* find a thread (this can cause a while(1) loop if all threads
					 * are blocked forever. but this should only be the case if there
					 * will be a bug in some other function (and I _WILL_ fix them if
					 * there will be some!
					 */
					found_a_thread = 0;
					while (!found_a_thread) {
						if (last_used_thread == (NUM_PARA_CONNS - 1))
							last_used_thread = 0;
						
						if (threads[last_used_thread].is_busy == 0) {
							found_a_thread = 1;
						} else {
							last_used_thread++;
						}
					}
					
					/* okay, now inform the thread about his new job */
					threads[last_used_thread].sinf = cli_sinf;
					threads[last_used_thread].is_busy = 1;
					
					/* last step: start the thread */
					if (write(threads[last_used_thread].pipefds[1], "A", 1) == -1) {
						perror("write");
						logstr(__FILE__, __LINE__, "write() returned with an error.");
					}
					
					/* don't free() cli_sinf here since the thread does it itself */
				}
			}
		}
	} while (1);
	/* NOTREACHED */
	return 0;
}


