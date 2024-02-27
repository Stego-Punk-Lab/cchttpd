# ccHTTPd

**ccHTTPd** is **a web server that can run C modules** and can optionally **serve content of PCAP files** (traffic recordings). This means that the server excutes C modules like other servers execute PHP code. Therefore, the server **comes with a library called *libcwdev* (C Web Development Library)**.

The project started as a student project in 2008 and was revived in 2023 when a BSD-licensed service was required for providing PCAP traffic file content easily over the web. The server still needs lots of work but is ready for testing.

### Why?

1. If you want to write websites in C ... here you go :)

2. If you need some BSD-licensed PCAP parser in a pipeline where GPL code is not allowed and you cannot use `tshark`, `wireshark` etc., you can use ccHTTPd.

3. You have some C code but want to attach the code to some web backend (can simply be done through ccHTTPd's *libcwdev*)

### Example

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

Again, start the server (e.g., through `make run`) and visit [http://127.0.0.1:8080/cgi-bin/modfoo.cm](http://127.0.0.1:8080/cgi-bin/modfoo.cm) to see if it works. If you want, pass a query parameter: [http://127.0.0.1:8080/cgi-bin/modfoo.cm?name=Max](http://127.0.0.1:8080/cgi-bin/modfoo.cm?name=Max).

Now, build and install the PCAP module, if you want to use it:

```
$ make modpcap
$ sudo make install_modpcap
```

**Note:** Please make sure that /var/www/cgi-bin/modpcap.cm is owned by the user you plan to run cchttpd with.

Finally, visit [http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap](http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap) to see if it works. It should provide you with the packet data for the pcap file *ip6.pcap*, located in */var/www/pcaps*. Place your *.pcap* files in */var/www/pcaps/* and you should be able to use them.

**Filters:** Per default, all packets are returned by `modpcap`. However, there is a way to explicitly *filter* certain types of packets using libpcap filter syntax:

```
$ GET 'http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap&filter=ip%20and%20udp'
num.packets=0000000000000002 

timestamp;caplen;wirelen;ethertype;l3prot;ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.cksum;ip6.src;ip6.dst;tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;tcp.cksum;udp.sport;udp.dport;udp.len;udp.cksum;dns.id;dns.flags;dns.opcode;dns.rcode;dns.questionRRs;dns.answerRRs;dns.authRRs;dns.additRRs;dns.questions;dns.answers; 
1694626462.161312;82;82;ip4;udp;127.0.0.1;127.0.0.1;4;5;0;20365;64;64;9135;;;;;;;;;;;;34003;53;48;65143;0xf078;Q/-/-/RD/-/-/AD/-;Q;0;1;0;0;1;"i.ytimg.com,A,1";;
1694626462.161637;338;338;ip4;udp;127.0.0.53;127.0.0.53;4;5;0;42993;64;1;52104;;;;;;;;;;;;53;34003;304;65399;0xf078;R/-/-/RD/RA/-/-/-;Q;0;1;16;0;1;"i.ytimg.com,A,1";"i.ytimg.com,A,1,5,4,142.250.184.214|i.ytimg.com,A,1,5,4,142.250.185.214|i.ytimg.com,A,1,5,4,216.58.206.54|i.ytimg.com,A,1,5,4,142.250.186.150|i.ytimg.com,A,1,5,4,142.250.74.214|i.ytimg.com,A,1,5,4,142.250.185.246|i.ytimg.com,A,1,5,4,172.217.16.150|i.ytimg.com,A,1,5,4,142.250.186.118|i.ytimg.com,A,1,5,4,142.250.184.246|i.ytimg.com,A,1,5,4,172.217.18.22|i.ytimg.com,A,1,5,4,172.217.16.214|i.ytimg.com,A,1,5,4,142.250.181.246|i.ytimg.com,A,1,5,4,142.250.185.182|i.ytimg.com,A,1,5,4,142.250.186.182|i.ytimg.com,A,1,5,4,142.250.186.54|i.ytimg.com,A,1,5,4,142.250.186.86";
```
```
$ GET 'http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap&filter=ip%20and%20(src%20host%2010.0.0.1%20or%20dst%20port%2053)'
num.packets=0000000000000001 

timestamp;caplen;wirelen;ethertype;l3prot;ip.src;ip.dst;ip.v;ip.hl;ip.tos;ip.id;ip.off;ip.ttl;ip.cksum;ip6.src;ip6.dst;tcp.sport;tcp.dport;tcp.seq;tcp.ack;tcp.off;tcp.flags;tcp.win;tcp.urp;tcp.cksum;udp.sport;udp.dport;udp.len;udp.cksum;dns.id;dns.flags;dns.opcode;dns.rcode;dns.questionRRs;dns.answerRRs;dns.authRRs;dns.additRRs;dns.questions;dns.answers;
1694626462.161312;82;82;ip4;udp;127.0.0.1;127.0.0.1;4;5;0;20365;64;64;9135;;;;;;;;;;;;34003;53;48;65143;0xf078;Q/-/-/RD/-/-/AD/-;Q;0;1;0;0;1;"i.ytimg.com,A,1";;
```

If you have a larger pcap file and want to test your filter, you might only want to parse the first 1,000 packets or so. In this case, use `limit=1000` as an URL parameter:

```
$ GET 'http://127.0.0.1:8080/cgi-bin/modpcap.cm?file=ip6.pcap&limit=3'
```

### Development Documentation for C Modules

This is to be done but *src/modfoo/modfoo.c* is rather self-explanatory.

### PCAPNG

The pcap-ng file format is supported only on Linux so far.

### Research

ccHTTPd with PCAP service is used as part of our steganography/network security research. Check out our other repositories:

- [Stego Punk Research Group, featuring our papers](https://stego-punk.net/)
- [Steffen's network covert channel tools](https://github.com/cdpxe/NetworkCovertChannels)
- [Steffen's network steganography online class](https://github.com/cdpxe/Network-Covert-Channels-A-University-level-Course)
