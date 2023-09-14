# ccHTTPd

--**Code will be uploaded soon**--

A web server that can run C modules and can optionally serve content of PCAP files. This means that the server excutes C modules like other servers execute PHP code. Therefore, ccHTTPd comes with a library called *libcwdev* (C Web Development Library).

ccHTTPd started as a student project in 2008 and was revived in 2023 when a BSD-licensed service was required for providing PCAP traffic file content easily over the web.

**Note:** ccHTTPd is for research groups and *not* tailored for production environments. The code is still immature and needs lots of additional security and reliability features before you can use it.
 
### Why?

1. If you want to write websites in C ... here you go :)

2. If you need some BSD-licensed PCAP parser in a pipeline where GPL code is not allowed and you cannot use `tshark`, `wireshark` etc., you can use ccHTTPd.

Here is some easy example of using the PCAP module:

```
$ GET http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap
num.packets=0000000000000006

timestamp;caplen;wirelen;ethertype;l3prot;ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.sum_raw;ip6.src;ip6.dst;tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;udp.sport;udp.dport;udp.len;udp.cksum
1694626462.161312;82;82;ip4;udp;127.0.0.1;127.0.0.1;4;5;0;20365;64;64;9135;;;;;;;;;;;34003;53;48;65143
1694626462.161637;338;338;ip4;udp;127.0.0.53;127.0.0.53;4;5;0;42993;64;1;52104;;;;;;;;;;;53;34003;304;65399
1694626465.306476;94;94;ip6;tcp;;;;;;;;;;::1;::1;44224;8080;259541359;0;10;2;50431;0;;;;
1694626465.306490;74;74;ip6;tcp;;;;;;;;;;::1;::1;8080;44224;0;261219081;5;20;0;0;;;;
1694626468.100424;94;94;ip6;tcp;;;;;;;;;;::1;::1;41510;22;392478046;0;10;2;50431;0;;;;
1694626468.100435;74;74;ip6;tcp;;;;;;;;;;::1;::1;22;41510;0;394155767;5;20;0;0;;;;
```

### Setup in a Nutshell

First, build the main server.

```
$ ./configure
$ make
$ sudo make install
```
Add `PCAP=NO` in front of `./configure` to disable support for *libpcap*.

**Note:** Please make sure that */var/log/cchttpd* is writeable by the user you are running this server with.

Now, test the server by running:

```
$ make run
```

Visit [http://127.0.0.1:8080](http://127.0.0.1:8080) to see if it works.

Now, let's build a sample C module and install it:

```
$ make modfoo
$ sudo make install_modfoo
```

**Note:** Please make sure that */var/www/cgi-bin/modfoo.cm* is owned by the user you plan to run cchttpd with.

Again, start the server (e.g., through `make run`) and visit [http://127.0.0.1:8080/cgi-bin/modfoo.cm](http://127.0.0.1:8080/cgi-bin/modfoo.cm) to see if it works.

Now, build and install the PCAP module, if you want to use it:

```
$ make modpcap
$ sudo make install_modpcap
```

**Note:** Please make sure that /var/www/cgi-bin/modpcap.cm is owned by the user you plan to run cchttpd with.

Finally, visit [http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap](http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap) to see if it works. It should provide you with the packet data for the pcap file *ip6.pcap*, located in */var/www/pcaps*. Place your *.pcap* files in */var/www/pcaps/* and you should be able to use them.

### Development Documentation for C Modules

This is to be done but *src/modfoo/modfoo.c* is rather self-explanatory.

