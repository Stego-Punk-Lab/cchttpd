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
#include <cwdev/libcwdev.h>

int mod_init(void)
{
	/* This message will solely appear in the STDOUT of your terminal running the server, not on the website. */
	printf("THE C MODULE INIT FUNCTION WAS EXECUTED!\n");
	return 0;
}

void mod_reqhandler(_cwd_hndl hndl, char *query_string)
{
	cwd_print(hndl, "<html><body><h1>Hello, C!</h1><p>Text Text Text</p><p>Try to add <code>?name=Max</code> to the URL.</p>");
	if (query_string) {
		char *name;
		
		cwd_print(hndl, "<p>Query-String='");
		cwd_print(hndl, query_string);
		cwd_print(hndl, "'</p><hr>");
		
		/* Example: Request http://127.0.0.1:8080/cgi-bin/modfoo.cm?name=Max to set the variable "name" */
		name = cwd_get_value_from_var(query_string, "name");
		if (name) {
			cwd_print(hndl, "value of variable 'name': ");
			cwd_print(hndl, name);
			cwd_print(hndl, "<br>");
		}
		free(name);
	} else {
		cwd_print(hndl, "query string is empty<br><hr>\n\n");
	}
	cwd_print(hndl, "</body></html>");
}

