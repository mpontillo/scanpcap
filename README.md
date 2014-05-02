scanpcap
=======

`scanpcap` is a little tool I wrote in order to brush up on C++ after many
years of inactivity.

It takes as an argument the name of a file in pcapng format, assumes that
all the packets inside are Ethernet packets, and outputs some basic statistics
about them, such as:

 - Number of packets
 - Maximum packet size
 - Minimum packet size
 - Count per Ethernet source address
 - Count per Ethernet destination address
