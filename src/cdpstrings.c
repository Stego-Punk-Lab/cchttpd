/*
 * ccHTTPd is distributed under the following license:
 *
 * Copyright (c) 2023 Steffen Wendzel <steffen (at) wendzel (dot) de> All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software must display the following acknowledgement: This product includes software developed by the <copyright holder>.
 * 4. Neither the name of the <copyright holder> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */
 
/* File is based on old WendzelNNTPd code; re-published under different license */

#include <string.h>
#include <stdlib.h>
#ifdef __svr4__
   #include <strings.h>
#endif
#include <stdio.h>
#include <ctype.h>

#include "cdpstrings.h"

#define PERROR_PREAMBLE "LibCDPstrings: File " __FILE__ ": "

/* return the value of a HTTP hdr field */
char *
CDP_return_linevalue(char *buf, char *key)
{
	extern char ACSarray[256]; /* ''anti case sensitive''-array */
	int start_value, i;
	int len_key = strlen(key);
	char *str; /* the new string this function will return */
	int len_str;
	u_int8_t do_search;
	
	/* ALERT: THIS FUNCTION ONLY WORKS IF UPPER-CASE STRING IS GIVEN! */
	
	/* make len_key chars of the buf upper case */
	for (i = 0; i < len_key; i++) {
		buf[i] = ACSarray[(int)buf[i]];
	}
	
	if (strncmp(buf, key, len_key) == 0) {
	   	/* okay, we need to find the value now. it can be in the same line:
	  	 * EITHER:   key:     value    or    key: value   or even   key:value
	   	 * OR:   key:  \r\n \r\n key  and the like ... I think this REALLY sux!
	   	 */
		buf += strlen(key);
		do_search = 1;
		while (do_search) {
		   	while (buf[0] == ' ' || buf[0] == '\t') {
		   		buf++;
		   	}
			
			i = 0;
		   	/* steht der wert jetzt endlich bei dieser positition? */
		   	if (buf[i] != '\r' && buf[i] != '\n') {
		   		/* extract the value */
		   		start_value = i;
				while (i < (int) strlen(buf) && buf[i] != '\r' && buf[i] != '\n')
					i++;
				
				len_str = i - start_value;
				if (len_str) { /* value should at least be 1 char long */
					str = (char *) calloc(len_str + 1, sizeof(char));
					if (!str) {
						perror(PERROR_PREAMBLE "key=calloc_L85");
						return NULL;
					}
					strncpy(str, buf + start_value, len_str);
					return str;
				}
				/* len_str == zero ; wtf??? */
				return NULL;
		   	} else {
		   		/* check for '\r\n ' */
		   		if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == ' ')
		   			i += 3;
				else
		   			do_search = 0;
		   	}
		}
	}
	return NULL;
}


