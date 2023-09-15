# ccHTTPd is distributed under the following license:
#
# Copyright (c) 2008,2023 Steffen Wendzel <steffen (at) wendzel (dot) de> All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software must display the following acknowledgement: This product includes software developed by the <copyright holder>.
# 4. Neither the name of the <copyright holder> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> AS IS AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 

include Makefile.inc

DESTCFLAGS=-DCONFDIR=\"$(CONFDIR)\"
CFLAGS= -O2 -c -Wall $(STACK_PROT) $(DESTCFLAGS)
CFLAGS+=-Wshadow -Wcast-qual -Wsign-compare -W
CFLAGS+=-Wextra -Wcast-align
#CFLAGS+=-Wunreachable-code

# These CFLAGS are only for C, not for C++!
#CFLAGS+=-Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations

CFLAGS+=$(ADD_CFLAGS)

BUILD=-DBUILD=\"`cat build`\"
GDBON=-ggdb -g
DEBUG=-DDEBUG $(GDBON)
BUILDFLAGS=-O2 $(STACK_PROT) $(ADD_LNKFLAGS)
HDRS=src/include/main.h src/include/cdpstrings.h src/include/mime.h src/include/yccw.h

all : init server lib

init :
	if [ ! -e $(BUILDDIR) ]; then mkdir $(BUILDDIR); fi
	if [ ! -d $(BUILDDIR) ]; then echo "Error: $(BUILDDIR) is not a directory!"; fi

server  : main.o server.o parse_reqhdr.o log.o cdpstrings.o create_resp.o
	expr `cat build` \+ 1 >build
	$(CC) $(DEBUG) $(BUILDFLAGS) -o bin/cchttpd main.o server.o \
	parse_reqhdr.o log.o cdpstrings.o create_resp.o \
	$(SOLNETLIBS) $(LIBDIRS) $(SOLNETLIBS) $(GCCLOCALPTHREAD) $(LIBPTHREAD) $(LIBDL)
	@#strip bin/cchttpd

strip : bin/cchttpd
	strip bin/cchttpd

lib : src/libcwdev/libcwdev.c src/libcwdev/include/libcwdev.h
	$(CC) $(DEBUG) $(BUILDFLAGS) -fPIC -shared -o bin/libcwdev.so -Isrc/libcwdev/include -W -Wall src/libcwdev/libcwdev.c

modfoo : src/modfoo/modfoo.c
	$(CC) $(DEBUG) $(BUILDFLAGS) -fPIC -shared -o bin/modfoo.cm -W -Wall src/modfoo/modfoo.c -lcwdev-1.0

modpcap : src/modpcap/modpcap.c
	$(CC) $(DEBUG) $(BUILDFLAGS) -DPCAP_BASEPATH=\"$(PCAPSDIR)\" -fPIC -shared -o bin/modpcap.cm -W -Wall src/modpcap/modpcap.c -lcwdev-1.0 -lpcap

updatestuff :
	if [ -f bin/modfoo.cm ]; then cp bin/modfoo.cm $(WWWDIR)/cgi-bin/test.cm; fi
	@# needs chmod +w /usr/lib/libcwdev-1.0.so for this user
	if [ -f bin/libcwdev.so ]; then cp bin/libcwdev.so /usr/lib/libcwdev-1.0.so; fi
	@# needs an existing /usr/lib/libcwdev with chmod +w for this user
	cp src/libcwdev/include/libcwdev.h /usr/include/cwdev/libcwdev.h

main.o : src/main.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/main.c

server.o : src/server.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/server.c

parse_reqhdr.o : src/parse_reqhdr.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/parse_reqhdr.c

log.o : src/log.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/log.c

cdpstrings.o : src/cdpstrings.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/cdpstrings.c

create_resp.o : src/create_resp.c $(HDRS)
	$(CC) $(DEBUG) $(BUILD) $(CFLAGS) $(INCDIRS) src/create_resp.c

run :
	./bin/cchttpd -l 127.0.0.1:8080 -vd

install : bin/cchttpd
	if [ ! -d /etc/cchttpd ]; then mkdir /etc/cchttpd; chmod og-w /etc/cchttpd; fi
	if [ ! -d /etc/cchttpd/errfiles ]; then mkdir /etc/cchttpd/errfiles; chmod og-w /etc/cchttpd/errfiles; fi
	cp -v errfiles/[1-9][0-9][0-9] /etc/cchttpd/errfiles
	chmod og-w /etc/cchttpd/errfiles/???
	if [ ! -d $(WWWDIR) ]; then mkdir $(WWWDIR); fi
	if [ ! -d $(WWWDIR)/index.html ]; then echo '<html><head><title>cchttpd is ready</title></head><body><h1>cchttpd is ready!</h1></body></html>' > $(WWWDIR)/index.html; fi
	if [ ! -d $(WWWDIR)/cgi-bin ]; then mkdir $(WWWDIR)/cgi-bin; chmod og-w $(WWWDIR)/cgi-bin; fi
	cp -v ./bin/cchttpd /usr/sbin/cchttpd
	if [ -f bin/libcwdev.so ]; then cp -v bin/libcwdev.so /usr/lib/libcwdev-1.0.so; fi
	if [ ! -d /usr/include/cwdev ]; then mkdir /usr/include/cwdev; chmod 755 /usr/include/cwdev; fi
	cp -v src/libcwdev/include/libcwdev.h /usr/include/cwdev/libcwdev.h
	touch /var/log/cchttpd; chmod og-w /var/log/cchttpd
	@echo "Please make sure that /var/log/cchttpd is writeable by the user you are running this server with."

install_modpcap :
	cp -v ./bin/modpcap.cm $(WWWDIR)/cgi-bin/modpcap.cm
	if [ ! -d $(PCAPSDIR) ]; then mkdir $(PCAPSDIR); chmod og-w $(PCAPSDIR); fi
	cp -v pcaps/ip6.pcap $(PCAPSDIR)/
	@echo "Please make sure that $(WWWDIR)/cgi-bin/modpcap.cm is owned by the user you plan to run cchttpd with."

install_modfoo :
	cp -v ./bin/modfoo.cm $(WWWDIR)/cgi-bin/modfoo.cm
	@echo "Please make sure that $(WWWDIR)/cgi-bin/modfoo.cm is owned by the user you plan to run cchttpd with."

exec : bin/cchttpd
	./bin/cchttpd -dl 127.0.0.1:8888

count : clean
	wc -l `find . -name '*.[chyl]'` | $(SORT)

clean :
	rm -fv bin/cchttpd *.core bin/*.cm bin/libcwdev.so `find . -name '*.o'` `find . -name '*~'`


