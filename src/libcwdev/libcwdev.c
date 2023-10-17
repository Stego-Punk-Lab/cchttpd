/*
 * ccHTTPd/libcwdev is distributed under the following license:
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

#include "libcwdev.h"
#include <sys/ioctl.h>

/* get_openfilelen():
 * This function is imported from WendzelNNTPd.
 * The function is herewith released under above-mentioned BSD license. */
int
get_openfilelen(FILE *fp)
{
	int len;
	
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	return len;
}

void
cwd_print(int fd_snd, char *str)
{
	int i;
	int len = strlen(str);
	if ((i = (write(fd_snd, str, len))) == -1) {
		fprintf(stderr, "write() error in yprint()\n");
	} else if (i < len) {
		fprintf(stderr, "write() wrote less than strlen(str) bytes in yprint()\n");
	} else {
		/* success */
	}
}

char *
cwd_get_value_from_var(char *query_in, char *varname)
{
	char *token = NULL, *subtoken = NULL, *saveptr1 = NULL, *saveptr2 = NULL;
	char *value = NULL;
	char *init_str = NULL;
	int query_len;
	char *query = NULL;
	
	/* first, create a copy of the query that we free afterwards */
	query_len = strlen(query_in);
	if (query_len) {
		query = (char *) calloc(query_len + 1, sizeof(char));
		if (query == NULL) {
			perror("calloc");
			return NULL;
		}
		memcpy(query, query_in, query_len);
	} else {
		return NULL;
	}

	init_str = query;
	while (1) {
		if ((token = strtok_r(init_str, "?&", &saveptr1)) == NULL) {
			/*fprintf(stderr, "strtok_r() returned NULL (init_str='%s', varname='%s')\n", init_str, varname);*/
			break;
		}
		init_str = NULL; /* should be NULL for future calls of strtok_r() */
		/*fprintf(stderr, "l1.token=%s\n", token);*/
		if (strncmp(token, varname, strlen(varname)) == 0) {
			/* call strtok_r() twice b/c need the 2nd token,
			 * which is the actual value, not the var-name */
			if ((subtoken = strtok_r(token, "=", &saveptr2)) == NULL)
				break;
			else if ((subtoken = strtok_r(NULL, "=", &saveptr2)) == NULL)
				break;
			
			/*fprintf(stderr, "    l2.token='%s'\n", subtoken);*/
			if ((value = calloc(sizeof(char), strlen(subtoken) + 1)) == NULL) {
				perror("calloc");
				free(query);
				return NULL;
			}
			memcpy(value, subtoken, strlen(subtoken));
			free(query);
			return value;
		} /*else {
			fprintf(stderr, "->'%s'!='%s'\n", varname, token);
		}*/
	}
	free(query);
	return NULL;
}

