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
#include <stdarg.h>

/*
 * These functions are more are less completely imported from my WendzelNNTPd
 */

int chk_file_sec(char *);

/* check if the permissions of the file are acceptable for this service and
 * if the file we try to open is a symlink (what could be part of an attack!)
 */
int
chk_file_sec(char *filename)
{
	/* based on the AstroCam source code I wrote in the past
	 * (see sf.net/projects/astrocam for details)
	 */
	int file;
	struct stat s;
	int sec_sd = 0; /* security shutdown */
	
	if ((file = open(filename, O_RDONLY)) < 0) {
		fprintf(stderr, "%s does not exist\n", filename);
		return -1;
	}
	
	if (fstat(file, &s) == -1) {
		fprintf(stderr, "fstat(%s) returned -1\n", filename);
		exit(1);
	}
	
	if (S_ISLNK(s.st_mode) || (S_IWOTH & s.st_mode) || (S_IWGRP &s.st_mode)) {
		fprintf(stderr, "File mode of %s has changed or file is a symlink!\n",
			filename);
		sec_sd = 1;
	}
	
	if (s.st_uid != 0 && s.st_uid != getuid() && s.st_uid != geteuid()) {
		fprintf(stderr, "Owner of %s is neither zero (root) nor my (e)uid!\n",
			filename);
		sec_sd = 1;
	}
	if (sec_sd) {
		return -1;
	}
	return 0;
}

void
logstr(char *file, int line, char *str)
{
	FILE *fp;
	time_t ltime;
	int len;
	char *buf;
	char tbuf[40] = {'\0'};
	
	ltime = time(NULL);
	strftime(tbuf, 39, "%a, %d %b %y %H:%M:%S", localtime(&ltime));
	
	len = strlen(tbuf) + strlen(file) + strlen(str) + 0x7f;
	if (!(buf = (char *)calloc(len, sizeof(char)))) {
		perror("logstr: buf = calloc()");
	}
	snprintf(buf, len - 1, "%s %s:%i: %s\n", tbuf, file, line, str);
	
	if (chk_file_sec(LOGFILE) != 0) {
		/* do nothing here -> this could lead to a while(1)! */
		syslog(LOG_DAEMON | LOG_NOTICE, "%s:%i: " LOGFILE
			" has insecure file permissions or is a symlink.",
			file, line);
	}
	if (!(fp = fopen(LOGFILE, "a+"))) {
		perror(LOGFILE);
	} else {
		fwrite(buf, strlen(buf), 1, fp);
		fclose(fp);
	}
	
	fprintf(stderr, "logstr: %s\n", str);
	syslog(LOG_DAEMON | LOG_NOTICE, "%s:%i: %s", file, line, str);
	free(buf);
}

/* log with a string parameter */
void
logstr1p(char *file, int line, char *str, char *para)
{
	char *buf;
	int len;
	
	len = strlen(str) + strlen(para) + 1;
	
	if (!(buf = (char *) calloc(len, sizeof(char)))) {
		perror("logstr1p: buf = calloc()");
	}
	if (strstr(para, "%%") != NULL) {
		logstr(file, line, "potential format string attack detected.\n");
	} else {
		snprintf(buf, len - 1, str, para);
		logstr(file, line, buf);
	}
	free(buf);
}



