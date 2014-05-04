scanpcap
========

`scanpcap` is a tool that scans through a packet capture file and prints
statistics about it.

It takes as an argument the name of a file (in pcapng format), assumes that
all the packets inside are Ethernet packets, and outputs some basic statistics
about them, such as:

 - Number of packets
 - Maximum packet size
 - Minimum packet size
 - Start, end, and elapsed time of the capture
 - Bytes captured (includingn truncated bytes)
 - Overall capture speed (bits captured divided by capture interval in seconds)
 - Count per Ethernet source address
 - Count per Ethernet destination address

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
    73759 packets
    Max size packet: 1514
    Min size packet: 54
    Start time: 1398903401.944119 seconds (Wed Apr 30 17:16:41 2014)
    End time: 1398904302.403040 seconds (Wed Apr 30 17:31:42 2014)
    Total time: 901 seconds (15.0 minutes)
    Total bytes captured: 50217316 bytes / 49040 kilobytes / 47 megabytes
    Overall capture speed: 435 Kbps (0 Mbps)

    Ethernet destinations:
       27521 00:e0:74:22:96:f3
         540 01:00:5e:00:00:57
         344 01:00:5e:00:00:2b
           1 01:00:5e:00:00:cf
           1 01:00:5e:7f:ff:5b
           3 33:33:00:00:00:01
          25 33:33:00:00:00:02
           8 33:33:00:00:00:f3
          60 33:33:00:00:00:22
          93 33:33:00:00:00:57
          74 33:33:00:01:00:02
         326 33:33:00:01:00:03
           1 33:33:ff:2b:29:66
           1 33:33:ff:4a:44:f3
           1 33:33:ff:59:92:c5
           1 33:33:ff:71:b6:3c
           1 33:33:ff:44:c9:af
           2 33:33:ff:d4:08:28
       44067 60:03:08:99:5c:27
         689 ff:ff:ff:ff:ff:ff

    Ethernet sources:
         124 00:23:67:b3:aa:cc
       44220 00:e0:74:22:96:f3
           1 10:1c:f3:5d:a0:df
          50 40:27:04:2d:d3:bf
         367 50:46:5d:15:47:6f
          54 5c:51:4f:9e:00:bb
       27554 60:03:08:99:5c:27
          36 60:fe:c5:ca:27:85
          17 74:e1:b6:af:f8:d2
          49 84:3a:74:33:67:4c
          20 88:53:95:7a:4d:ce
          42 88:cb:87:be:b1:b3
         318 8c:3a:e3:4a:44:f3
           1 8c:7b:9d:e1:df:75
         338 9c:2a:70:74:d4:21
         434 a4:17:31:d0:c7:d7
           6 ac:cf:ec:ed:31:32
          33 b8:e8:56:1d:48:a2
          11 b8:e8:56:a2:c6:d2
          39 c4:85:08:f2:be:f3
          45 dc:9b:9c:1a:24:de

License
=======

`scanpcap` is licensed under the Apache 2.0 license.
