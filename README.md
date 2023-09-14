# ccHTTPd

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
