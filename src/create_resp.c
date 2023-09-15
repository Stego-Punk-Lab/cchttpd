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
#include "mime.h"

int set_errpage(httphdr_t *, int);

extern char *htdocs_path;
extern modlist_t *modlist;
extern pthread_mutex_t mutex_cmodload;

// will be extern after read by config file
char *indexfiles[] = {
	"index.html",
	"index.htm",
	"index.xhtml",
	NULL
};

static char hdr_server[] = "Server: cchttpd/" CCHTTPD_VER;
static char res_200[] = "200 OK";
static char err_400[] = "400 Bad Request";
//static char err_401[] = "401 Unauthorized";
static char err_403[] = "403 Forbidden";
static char err_404[] = "404 Not Found";
static char err_405[] = "405 Method Not Allowed (currently only HEAD/GET/POST supported)";
static char err_500[] = "500 Internal Server Error";

/* Only use this macro WITHIN THIS FILE !!! The ret-val heavily depends on create_respinf() */
#define CCALLOC(_buf_, _size_) if (!(_buf_ = (char *) calloc(_size_, sizeof(char)))) {	\
				perror("calloc");					\
				logstr(__FILE__, __LINE__, "calloc ret error");		\
				return ERROR_MEMALLOC;					\
			}

int
set_errpage(httphdr_t *o_hdr, int error)
{
	int len;
	char *errpg;
	struct stat st;
	
	if (o_hdr->abs_path)
		free(o_hdr->abs_path);
	if (o_hdr->path)
		free(o_hdr->path);
	
	len = strlen(DEFAULT_ERRFILEDIR) + 1 + 3 /* "404" */ + 1;
	
	CCALLOC(o_hdr->abs_path, len)
	CCALLOC(o_hdr->path, len)
	
	switch(error) {
	case ERROR_FORBIDDEN: errpg = "/403"; break;
	case ERROR_404: errpg = "/404"; break;
	case ERROR_BADREQUEST: errpg = "/400"; break;
	/* Don't use Method Not Allowed since we don't send back anything then! */
	case ERROR_METHOD_NOT_ALLOWED: errpg = "/405"; break;
	case ERROR_UNDEFINED: errpg = "/500"; break;
	default:
		printf("---------!!! heavy error (err=%i) !!!---------\n", error);
		errpg = "/500";
		break;
	}
	snprintf(o_hdr->abs_path, len, DEFAULT_ERRFILEDIR "%s", errpg);
	snprintf(o_hdr->path, len, DEFAULT_ERRFILEDIR "%s", errpg);
	
	stat(o_hdr->abs_path, &st);
	if (o_hdr->content_length != NULL) {
		free(o_hdr->content_length);
		o_hdr->content_length = NULL;
	}
	if (st.st_size > 999) {
		/* Todo: In this case we don't send Content-Len */
	}
	CCALLOC(o_hdr->content_length, 5)
	snprintf(o_hdr->content_length, 4, "%3u", (unsigned int) st.st_size);
	/* this is needed for the server mainloop to send the file */
	o_hdr->filesize = st.st_size;
	
	return 0;
}

/* chk_path():
 * 1. check if path contains format string parameter like %s
 * 2. check the path for something like /var/www/../../../etc/passwd 
 */

int
chk_path(char *path)
{
	char cur_wd[PATH_MAX + 1] = { '\0' };
	char new_wd[PATH_MAX + 1] = { '\0' };
	char *tmp_path = NULL;
	int chdir_success = 0;
	int strlen_path;
	
	/* 1. check for format string parameter */
	if(strstr(path, "%%") != NULL) {
		return -1;
	}
	
	/* 2. now check the directory path itself */
	if (strstr(path, "..") != NULL) {
		/* save our current pwd */
		if (getcwd(cur_wd, PATH_MAX) == NULL) {
			perror("getcwd");
			return -1;
		}
		
		/* get the new path */
		if (chdir(path) != 0) {
			int i;
			int found;
			
			/* remove the filename */
			
			for (strlen_path = 0; path[strlen_path] != '\0'; strlen_path++)
				;
			
			tmp_path = (char *) calloc(strlen_path + 1, sizeof(char));
			if (!tmp_path) {
				logstr(__FILE__, __LINE__, "calloc() mem error\n");
				return ERROR_MEMALLOC;
			}
			strncpy(tmp_path, path, strlen_path);
			for (i = strlen(tmp_path) - 1, found = 0; !found && i >= 0; i--) {
				if (tmp_path[i] == '/') {
					tmp_path[i] = '\0';
					found = 1;
				}
			}
			/* did not found something??? */
			if (!found) {
				/* this is not possibly */
				printf("----| internal error in chk_path() |----\n");
				free(tmp_path);
				return -1;
			}
			
			/* okay, successfully modified the path now try again */
			if (chdir(tmp_path) != 0) {
				/* still doesn't work ==> no permission or doesn't exist. */
				free(tmp_path);
				return 0;
			}
			free(tmp_path);
			chdir_success = 1;
		} else {
			chdir_success = 1;
		}
		
		if (chdir_success) {
			/* okay, now since we're in a new dir, get it */
			if (getcwd(new_wd, PATH_MAX) == NULL) {
				perror("getcwd()");
				return -1;
			}
			/* okay, we now have the new working dir in new_wd. now go back to our old wd! */
			if (chdir(cur_wd) != 0)
				logstr1p(__FILE__, __LINE__,
					"unable to chdir back to my old working dir (%s).", cur_wd);
			
			/* ... and check if we are still in the htdocs dir (or in the error dir) ... */
			if (strncmp(new_wd, DEFAULT_HTDOCS, strlen(DEFAULT_HTDOCS)) == 0
			 || strncmp(new_wd, DEFAULT_ERRFILEDIR, strlen(DEFAULT_ERRFILEDIR)) == 0) {
				/* okay, fine */
				return 0;
			}
			
			/* did not found a "good" path. seems to be a hack attempt ... */
			return -1;
		}
	}
	
	return 0;
}

/* compose a response message and return it to the socket mainloop of the thread
 * that will send the response back to the client. Also return an error-code (0
 * means success).
 */

int
create_respinf(httphdr_t *i_hdr, httphdr_t *o_hdr)
{
	int error = 0;
	char *query_string = NULL;
	int i;
	int len;
	u_int8_t index_ok = 0;
	int bodyfile = -1;
	
	/* check the path, if method is {GET,HEAD,POST} */
	switch (i_hdr->method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_HEAD:
	case HTTP_METHOD_POST:
		/* the path must be something like (quoted from the RFC)
		 * "http:" "//" host [ ":" port ] [ abs_path [ "?" query ]]
		 */
		if (i_hdr->uri[0] != '/') {
			error = ERROR_BADREQUEST;
			set_errpage(o_hdr, error);
			break;
		}
		//len = strlen(i_hdr->uri);
		i = 1;
		while (i_hdr->uri[i] != '?' && i_hdr->uri[i] != '\0')
			i++;
		/* either: /path */
		if (i_hdr->uri[i] == '\0') {
			o_hdr->path = i_hdr->uri;
			query_string = NULL;
		} else {
			/* replace '?' with '\0' to seperate both parts of the str */
			i_hdr->uri[i] = '\0';
			o_hdr->path = i_hdr->uri;
			query_string = i_hdr->uri + i + 1;
			/* not really needed but ... if strlen is 0: set to NULL
			 * (I maybe can safe time later because of this) */
			if (query_string[0] == '\0')
				query_string = NULL;
		}
		
		/* set the full path */
		len = strlen(htdocs_path) + strlen(o_hdr->path) + 1;
		CCALLOC(o_hdr->abs_path, len + 1)
		snprintf(o_hdr->abs_path, len + 1, "%s%s", htdocs_path, o_hdr->path);
		
		/* check if the user tries something like GET /../../../../etc/passwd or %x */
		if (chk_path(o_hdr->abs_path) != 0) {
			logstr1p(__FILE__, __LINE__, "User tried hack attemt to disallowed path (chk_path() check) (blocked)\n", o_hdr->abs_path);
			error = ERROR_FORBIDDEN;
			set_errpage(o_hdr, error);
			break;
		}
		
		/* check, if the path is possibly to access */
#ifdef DEBUG
		fprintf(stderr, "abs_path='%s'\n", o_hdr->abs_path);
#endif
		if (access(o_hdr->abs_path, R_OK) != 0) {
			if (errno == ENOENT) {
				error = ERROR_404;
				set_errpage(o_hdr, error);
				logstr(__FILE__, __LINE__, "File not found (404)\n");
				break;
			} else {
				perror("access");
				logstr1p(__FILE__, __LINE__, "No read access: %s\n", o_hdr->abs_path); /* already checked for format-string inclusion w/ chk_path() */
				error = ERROR_FORBIDDEN;
				set_errpage(o_hdr, error);
				break;
			}
		} else {
			struct stat st;
			int stat_ret = 0;
			
			/* Get file information */
			stat_ret = stat(o_hdr->abs_path, &st);
			if (stat_ret == -1) {
				perror("stat");
				logstr(__FILE__, __LINE__, "stat returned error\n");
				error = ERROR_UNDEFINED;
				set_errpage(o_hdr, error);
				break;
			}
			
			/* Check file type. Only accept regular files return 'Forbidden' in the
			 * case it isn't. Also check for indexfiles if this is a dir and return
			 * a indexfile if needed.
			 */
			if (!S_ISREG(st.st_mode)) {
				if (S_ISDIR(st.st_mode)) {
					int strlen_abs_path;
					int strlen_indexfiles_i;
					for (i = 0; indexfiles[i] != NULL && !index_ok; i++) {
						char *newpath;
						
						for (strlen_abs_path = 0; o_hdr->abs_path[strlen_abs_path] != '\0'; strlen_abs_path++)
							;
						for (strlen_indexfiles_i = 0; indexfiles[i][strlen_indexfiles_i] != '\0'; strlen_indexfiles_i++)
							;
						
						CCALLOC(newpath, strlen_abs_path + strlen_indexfiles_i + 1 + 1)
						strncpy(newpath, o_hdr->abs_path, strlen_abs_path);
						newpath[strlen_abs_path] = '/';
						strncpy(newpath + strlen_abs_path + 1, indexfiles[i], strlen_indexfiles_i);
						/* must exist */
						if (access(newpath, F_OK) == 0) {
							/* must be readable + a file (what means first to update stat info) */
							stat_ret = stat(newpath, &st);
							if (stat_ret == -1) {
								perror("stat");
								logstr(__FILE__, __LINE__, "stat returned error\n");
								error = ERROR_UNDEFINED;
								set_errpage(o_hdr, error);
								break;
							}
							if (access(newpath, R_OK) == 0 && S_ISREG(st.st_mode)) {
								char *tmp_c;
								int tmp_c_len;
								
								/* okay, found a new file */
								free(o_hdr->abs_path);
								/* update abs_path and path! */
								o_hdr->abs_path = newpath;
								
								tmp_c_len = strlen(o_hdr->path) + 1 + strlen_indexfiles_i + 1;
								CCALLOC(tmp_c, tmp_c_len);
								snprintf(tmp_c, tmp_c_len, "%s/%s", o_hdr->path, indexfiles[i]);
								free(o_hdr->path);
								o_hdr->path = tmp_c;
								
								index_ok = 1;
							} else {
								free(newpath);
							}
						} else {
							free(newpath);
						}
					}
					/* if still not found */
					if (!index_ok) {
						/* return forbidden since directory listing is not available */
						logstr1p(__FILE__, __LINE__, "Forbidden (no index file at %s)\n",
							o_hdr->path);
						error = ERROR_FORBIDDEN;
						set_errpage(o_hdr, error);
						break;
					}
				} else {
					logstr1p(__FILE__, __LINE__, "Forbidden (%s not a regular file)\n",
						o_hdr->path);
					error = ERROR_FORBIDDEN;
					set_errpage(o_hdr, error);
					break;
				}
			}
			
			/* Check if this is a C-Module (we know that the file exists if we are at
			 * this point of the code). */
			{
				int strlen_o_hdr_path = strlen(o_hdr->path);
				
				if (strncmp(o_hdr->path, "/cgi-bin", 8) == 0 && o_hdr->path[strlen_o_hdr_path-3] == '.'
						&& o_hdr->path[strlen_o_hdr_path-2] == 'c' && o_hdr->path[strlen_o_hdr_path-1] == 'm' ) {
					/* filename is *.cm and it is located in /cgi-bin/... -- good ...
					 * not lets check if this file has chmod +x for its user and
					 * this file is chown'ed by our effective UID! */
					if ((st.st_mode & S_IXUSR) && (st.st_uid == geteuid())) {
						/* okay, check if it is already loaded and load if, if not.
						 * but don't execute it here since create_respbuf() or maybe
						 * do_server() will do this. TODO: create_respbuf() OR do_server???
						 */
						u_int8_t is_loaded = 0;
						modlist_t *mptr;
						void *handle;
						yfptrs_t *yfptrs;
						yfptrs = (yfptrs_t *) calloc(1, sizeof(yfptrs_t));
						if (!yfptrs) {
							logstr(__FILE__, __LINE__, "calloc error. not enough mem.");
							return ERROR_MEMALLOC;
						}
						
						mptr = modlist;
						while (mptr != NULL && !is_loaded) {
							if (strcmp(mptr->path, o_hdr->path) == 0) {
								is_loaded = 1;
							} else {
								mptr = mptr->next;
							}
						}
						
						if (!is_loaded) {
							char *_path;
							int strlen_ohdr_path = 0;
							
							/* lock mutex */
							if (pthread_mutex_lock(&mutex_cmodload) != 0) {
								logstr(__FILE__, __LINE__, "unable to do pthread_mutex_lock()\n");
							}
							
							mptr = modlist;
							while (mptr != NULL && !is_loaded) {
								if (strcmp(mptr->path, o_hdr->path) == 0) {
									is_loaded = 1;
								} else {
									mptr = mptr->next;
								}
							}
							/* yes -- it _IS_ a goto statement! */
							if (is_loaded)
								goto prefinish_module_load; /* this also unlocks the mutex */
							
							/* This is slow but: search the module AGAIN since it could be loaded
							 * by another thread within the meantime (_could_ be the case ...)
							 */
							
							
							/* could not find the loaded module -> load it now */
							handle = dlopen(o_hdr->abs_path, RTLD_LOCAL | RTLD_LAZY);
							if (!handle) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__, "dlopen() error\n");
								error = ERROR_FORBIDDEN;
								set_errpage(o_hdr, error);
								break;
							}
#ifdef DEBUG
							fprintf(stderr, "dynamic object loaded...\n");
#endif
	
							/* find the address of function and data objects */
							yfptrs->init = (int (*) (void)) dlsym(handle, "mod_init");
							if (!yfptrs->init) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__,
									"no mod_init() func found in C module\n");
								error = ERROR_FORBIDDEN;
								set_errpage(o_hdr, error);
								break;
							}
	
							yfptrs->req_handler = (void (*) (_cwd_hndl, char *)) dlsym(handle, "mod_reqhandler");
							if (!yfptrs->req_handler) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__,
									"no mod_reqhandler() func found in C module\n");
								error = ERROR_FORBIDDEN;
								set_errpage(o_hdr, error);
								break;
							}
							
							/* before adding the module finaly to our list,
							 * run the init function and check the return value (must be 0). */
							if (yfptrs->init() != 0) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__, "Module init returned != 0. "
									"Unable to load this module.");
								error = ERROR_FORBIDDEN;
								set_errpage(o_hdr, error);
								break;
							}
							
							/* add this module to the slist of loaded modules */
							mptr = (modlist_t *) calloc(1, sizeof(modlist_t));
							if (!mptr) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__, "calloc: not enough mem");
								return ERROR_MEMALLOC;
							}
							bzero(mptr, sizeof(modlist_t));
							
							strlen_ohdr_path = strlen(o_hdr->path);
							_path = (char *) calloc(1, strlen_ohdr_path + 1);
							if (!_path) {
								if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
									logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
								}
								logstr(__FILE__, __LINE__, "calloc: not enough mem");
								return ERROR_MEMALLOC;
							}
							memcpy(_path, o_hdr->path, strlen_ohdr_path);
							mptr->path = _path;
							
							mptr->fptrs = yfptrs;
							
							/* now really add it to our slist */
							if (modlist == NULL) {
								modlist = mptr;
							} else {
								modlist_t *mptrb;
								
								for (mptrb = modlist; mptrb->next != NULL; mptr = mptr->next)
									;
								mptrb->next = mptr;
							}
							is_loaded = 1;
							
prefinish_module_load:			
							if (pthread_mutex_unlock(&mutex_cmodload) != 0) {
								logstr(__FILE__, __LINE__, "unable to do pthread_mutex_unlock()\n");
							}
						}
						
						/* okay, the module is loaded. execute it and store the output in a
						 * buffer that we will send back to the client in create_respbuf() */
						if (is_loaded) {
							_cwd_hndl hndl;
							memcpy(o_hdr->cgi_tmpfile_name, "cmod.XXXXXX\0", 11); /* cannot use string directly as it will be modified! */
							
							if ((bodyfile = mkstemp(o_hdr->cgi_tmpfile_name)) == -1) {
								perror("mkstemp()");
								logstr(__FILE__, __LINE__, "mkstemp() error");
								error = ERROR_UNDEFINED;
								set_errpage(o_hdr, error);
								break;
							}
							
							/* execute the request handler routine */
							o_hdr->cgi_file = bodyfile; //TODO: redundant?
							hndl.fd_snd = bodyfile;
							mptr->fptrs->req_handler(hndl, query_string);							
							
							/* VERY important: update the stat information for the rest of the
							 * code of this functions (to set the date, content-length and the
							 * like). */
							if (fstat(bodyfile, &st) == -1) {
								perror("fstat");
								logstr(__FILE__, __LINE__, "fstat() error\n");
							}
							
							/* finaly made it. */
							o_hdr->is_cmod = 1;
						} else {
							logstr(__FILE__, __LINE__, "module not loaded (internal error)\n");
							error = ERROR_UNDEFINED;
							set_errpage(o_hdr, error);
							break;
						}
					} else {
						logstr(__FILE__, __LINE__, "Permission denied (wrong user or no exec access?)\n");
						error = ERROR_FORBIDDEN;
						set_errpage(o_hdr, error);
						break;
					}
				}
			}
			
			/* Set 'Last-Modified:' */
			{
				struct tm gtm;
				char *buf;
				
				CCALLOC(buf, 31)
				gmtime_r(&st.st_mtime, &gtm);
				strftime(buf, 30, "%a, %d %b %Y %H:%M:%S GMT", &gtm);
				o_hdr->last_modified = buf;
#ifdef DEBUG
				printf("Last-Modified: %s\n", buf);
#endif
			}
			/* Set 'Content-Length:' */
			if (i_hdr->method & (HTTP_METHOD_GET | HTTP_METHOD_HEAD)) {
				/* 1st part: for non-cgi */
				if (o_hdr->is_cmod == 0) {
					/* Only add the size, if the size is -lt 2 GB */
					if (st.st_size < 0x7fffffff) {/* 2 GBytes! */
						char *buf;
						
						CCALLOC(buf, 12)
						snprintf(buf, 11, "%u", (unsigned int) st.st_size);
						o_hdr->content_length = buf;
						/* this is needed for the server mainloop to send the file */
						o_hdr->filesize = st.st_size;
					}
				}
				/* 2nd part: for /cgi-bin only */
				else {
					char *buf;
					
					/* get the content len based on the information of the fd */
					lseek(bodyfile, 0, SEEK_SET);
					if (ioctl(bodyfile, FIONREAD, &o_hdr->filesize) == -1) {
						perror("ioctl()");
						logstr(__FILE__, __LINE__, "ioctl() error");
						o_hdr->filesize = 0;
						break;
					}
										
					CCALLOC(buf, 12)
					snprintf(buf, 11, "%u", (unsigned int) o_hdr->filesize);
					o_hdr->content_length = buf;
				}
			}
		}
		break;
	default:
		error = ERROR_METHOD_NOT_ALLOWED;
		set_errpage(o_hdr, error);
		break;
	}
	
#ifdef DEBUG
	printf("path ='%s'\n", o_hdr->path);
	printf("query='%s'\n", query_string);
#endif
	/* set the 'Date:' */
	{
		time_t t;
		struct tm gtm;
		char *buf;
		
		CCALLOC(buf, 31)
		t = time(NULL);
		gmtime_r(&t, &gtm);
		strftime(buf, 30, "%a, %d %b %Y %H:%M:%S GMT", &gtm);
		o_hdr->date = buf;
#ifdef DEBUG
		printf("Date: %s\n", buf);
#endif
	}
	
	/* Connection stuff */
	{
		o_hdr->connection = i_hdr->connection;
#ifdef DEBUG
		printf("o_hdr->connection = 0x%x\n", o_hdr->connection);
#endif
	}
	
	/* Content-Type */
	if (error) {
		o_hdr->content_type = text_html;
	} else {
		char *ptr = NULL;
		u_int8_t found = 0;
		int suffix_len;
		int8_t other_len;
		
		/* find the last '.' in the string */
		len = strlen(o_hdr->path);
		for (i = len - 1; !ptr && i; i--) {
			if (o_hdr->path[i] == '.')
				ptr = (o_hdr->path + i + 1);
		}
		/* if we didn't found anything, let it be text/plain */
		if (!ptr || ptr[0] ==  '\0') {
			/* the index-files are usually of the type .html ;-) */
			o_hdr->content_type = text_plain;
		} else {
			/* okay, we need to find out what MIME type it is */
			
			/* hopefully faster than libc strlen() */
			for (suffix_len = 1; ptr[suffix_len] != '\0'; suffix_len++)
				;
			
			for (i = 0; mime_types[i].suffix != NULL && !found; i++) {
				for (other_len = 1; mime_types[i].suffix[other_len] != '\0'; other_len++)
					;
				if (suffix_len == other_len)
					if (strcmp(ptr, mime_types[i].suffix) == 0) {
						found = 1;
						o_hdr->content_type = mime_types[i].mime_name;
					}
			}
			if (!found) {
				o_hdr->content_type = text_plain;
			}
		}
	}
	
	return error;
}

/* Create a buffer to send out based on the information in shdr (returned by
 * create_respinf()).
 */

char *
create_respbuf(httphdr_t *shdr, int error)
{
	int hdrlen = 0;
	int nxtlen = 0;
	char *res;
	char *pos;
	char *status_line;

	if (error) {
		switch(error) {
		case ERROR_BADREQUEST:
			hdrlen += strlen(err_400);
			status_line = err_404;
			break;
		case ERROR_404:
			hdrlen += strlen(err_404);
			status_line = err_404;
			break;
		case ERROR_FORBIDDEN:
			hdrlen += strlen(err_403);
			status_line = err_403;
			break;
		case ERROR_METHOD_NOT_ALLOWED:
			hdrlen += strlen(err_405);
			status_line = err_405;
			break;
		case ERROR_UNDEFINED:
		case ERROR_MEMALLOC:
		default:
#ifdef DEBUG
			printf("UNKNOWN ERROR: 0x%x\n", error);
#endif
			hdrlen += strlen(err_500);
			status_line = err_500;
			break;
		}
	} else {
		hdrlen += strlen(res_200);
		status_line = res_200;
	}
	
	hdrlen += 9; /* "HTTP/1.1 " */
	hdrlen += 2; /*\r\n*/
	
	hdrlen += strlen(hdr_server) + 2;
	
	if (shdr->last_modified)
		hdrlen += strlen(shdr->last_modified) + 2 + 15 /* "Last-Modified: " */;
	if (shdr->content_length)
		hdrlen += strlen(shdr->content_length) + 2 + 16 /* "Content-Length: " */;
	if (shdr->date)
		hdrlen += strlen(shdr->date) + 2 + 6 /* "Date: " */;
	// Todo: Still missing Connection: ...TE...
	if (shdr->connection & CONNECTION_KEEPALIVE)
		hdrlen += 22 /* "Connection: Keep-Alive" */ + 2;
	else
		hdrlen += 17 /* "Connection: Close" */ + 2;
	if (shdr->content_type)
		hdrlen += strlen(shdr->content_type) + 2 + 14  /* "Content-Type: " */;
	
	hdrlen += 2; /* trailing CRLF */
	
	/* create the hdr */	
	res = (char *) calloc(hdrlen + 1, sizeof(char));
	if (!res) {
		return NULL;
	}
	
	pos = res;
	
/* *** Create the Hdr *** */
	
	/* STATUS Line */
	nxtlen = 9 /*"HTTP/1.1 "*/ + strlen(status_line) + 2;
	snprintf(pos, nxtlen + 1, "HTTP/1.1 %s\r\n", status_line);
	pos += nxtlen;
	
	/* GENERAL Hdr */
	if (shdr->connection & CONNECTION_KEEPALIVE) {
		nxtlen = 22 /*"Connection: Keep-Alive"*/ + 2;
		snprintf(pos, nxtlen + 1, "Connection: Keep-Alive\r\n");
		pos += nxtlen;
	} else {
		nxtlen = 17 /*"Connection: Close"*/ + 2;
		snprintf(pos, nxtlen + 1, "Connection: Close\r\n");
		pos += nxtlen;
	}
	
	if (shdr->date) {
		nxtlen = strlen(shdr->date) + 6 /* "Date: " */ + 2;
		snprintf(pos, nxtlen + 1, "Date: %s\r\n", shdr->date);
		pos += nxtlen;
	}
	
	/* ENTITY Hdr */
	if (shdr->last_modified) {
		nxtlen = strlen(shdr->last_modified) + 15 /* 'Last-Modified: ' */ + 2;
		snprintf(pos, nxtlen + 1, "Last-Modified: %s\r\n", shdr->last_modified);
		pos += nxtlen;
	}
	
	if (shdr->content_length) {
		nxtlen = strlen(shdr->content_length) + 16 /* "Content-Length: " */ + 2;
		snprintf(pos, nxtlen + 1, "Content-Length: %s\r\n", shdr->content_length);
		pos += nxtlen;
	}
	
	if (shdr->content_type) {
		nxtlen = strlen(shdr->content_type) + 14  /* "Content-Type: " */ + 2;
		snprintf(pos, nxtlen + 1, "Content-Type: %s\r\n", shdr->content_type);
		pos += nxtlen;
	}
	
	/* RESPONSE Hdr */
	nxtlen = strlen(hdr_server) + 2;
	snprintf(pos, nxtlen + 1, "%s\r\n", hdr_server);
	pos += nxtlen;
	
	strncat(pos, "\r\n", 2);
	return res;
}


