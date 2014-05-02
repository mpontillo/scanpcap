project(keyvpn CXX C)
cmake_minimum_required(VERSION 2.6)

add_executable(
                # executable name
                scanpcap

                # soure files
                scanpcap.cpp
              )

target_link_libraries(scanpcap pcap)
