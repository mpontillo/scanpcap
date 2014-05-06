scanpcap
========

`scanpcap` is a tool that scans through a packet capture file and prints
statistics about it.

It takes as an argument the name of a file (in pcapng format), and outputs
some basic statistics about them, such as:

 - Number of packets
 - Number of Ethernet packets
 - Number of ARP packets
 - Maximum packet size
 - Minimum packet size
 - Start, end, and elapsed time of the capture
 - Bytes captured (includingn truncated bytes)
 - Overall capture speed (bits captured divided by capture interval in seconds)

For Ethernet links, also reports on:
 - Count of packets per Ethernet source address
 - Count of packets per Ethernet destination address
 - Any ARP mappings observed

See Also
========

Please note that `scanpcap` was written as a learning tool. Since it seemed
useful, I decided to release it.

However, if you are trying to do serious work with packet capturing, it
might be better to look at a more advanced tool, such as:

 - [Wireshark](http://www.wireshark.org/)
 - [Bro Network Security Monitor](http://www.bro.org/)

Building
========

`scanpcap` includes a CMake build file. To build, ensure `cmake` is installed.
Then do something like this:

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make

Example Output
==============

    $ ./scanpcap ~/example.pcapng
    6938 packets
    6938 Ethernet packets
    940 ARP packets
    Min size packet: 42
    Max size packet: 1514
    Average size packet: 101
    Start time: 1399395954.205360 seconds (Tue May  6 10:05:54 2014)
    End time: 1399397455.059807 seconds (Tue May  6 10:30:55 2014)
    Total time: 1501 seconds (25.0 minutes)
    Total bytes captured: 704371 bytes / 687 kilobytes / 0 megabytes
    Overall capture speed: 3 Kbps (0 Mbps)

    Ethernet destinations:
           3 00:11:32:05:b8:58
           4 00:19:5e:67:97:1c
           4 00:1e:be:cd:e4:b0
           6 00:23:7d:8d:d8:cd
        1456 00:24:a5:af:24:85
           4 00:24:d7:3f:ba:e0
           5 00:d0:2d:22:12:23
         207 01:00:5e:00:00:01
          87 01:00:5e:00:00:fb
         332 01:00:5e:7f:ff:fa
         735 01:80:c2:00:00:00
         130 04:a1:51:82:8b:23
           4 06:a1:51:21:d5:ce
           3 10:1c:0c:6b:53:00
          81 33:33:00:00:00:fb
          12 33:33:00:01:00:02
          66 40:6c:8f:3a:09:cc
        1778 60:03:08:a8:5c:30
           2 70:de:e2:4a:13:50
          25 90:2b:34:dc:7e:9d
           2 94:de:80:6b:ca:55
           5 d8:d1:cb:5d:c0:3b
          34 f8:1e:df:df:f7:c0
        1953 ff:ff:ff:ff:ff:ff

    Ethernet sources:
          69 00:11:32:05:b8:58
           1 00:19:5e:67:97:1c
           1 00:1e:be:cd:e4:b0
          18 00:23:7d:8d:d8:cd
        1572 00:24:a5:af:24:85
           1 00:24:d7:3f:ba:e0
         396 00:6b:9e:9a:f1:32
          18 00:d0:2d:22:12:23
        1374 04:a1:51:82:8b:23
          21 06:a1:51:21:d5:ce
          48 10:1c:0c:6b:53:00
          31 10:bf:48:ee:4a:41
         133 40:6c:8f:3a:09:cc
          12 4c:b1:99:05:f6:4f
        2411 60:03:08:a8:5c:30
           5 68:5b:35:a5:fa:9a
           3 70:de:e2:4a:13:50
          43 90:2b:34:dc:7e:9d
          53 94:de:80:6b:ca:55
         126 bc:3b:af:49:05:ab
          49 d8:d1:cb:5d:c0:3b
         553 f8:1e:df:df:f7:c0

    ARP table:
        172.16.42.1          00:24:a5:af:24:85
        172.16.42.10         00:1e:be:cd:e4:b0
        172.16.42.110        00:19:5e:67:97:1c
        172.16.42.150        d8:d1:cb:5d:c0:3b
        172.16.42.152        06:a1:51:21:d5:ce
        172.16.42.156        94:de:80:6b:ca:55
        172.16.42.157        90:2b:34:dc:7e:9d
        172.16.42.161        f8:1e:df:df:f7:c0
        172.16.42.170        00:d0:2d:22:12:23
        172.16.42.171        70:de:e2:4a:13:50
        172.16.42.178        10:1c:0c:6b:53:00
        172.16.42.180        00:6b:9e:9a:f1:32
        172.16.42.183        00:24:d7:3f:ba:e0
        172.16.42.192        00:11:32:05:b8:58
        172.16.42.196        60:03:08:a8:5c:30
        172.16.42.197        00:23:7d:8d:d8:cd
        172.16.42.199        40:6c:8f:3a:09:cc
        172.16.42.2          04:a1:51:82:8b:23
        172.16.42.20         40:6c:8f:3a:09:cc
        172.16.42.21         40:6c:8f:3a:09:cc

License
=======

`scanpcap` is licensed under the Apache 2.0 license.
