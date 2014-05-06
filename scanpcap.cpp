/*
 * Copyright 2014 Mike Pontillo
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may 
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>

#include <string>
#include <map>
#include <iterator>
#include <ctime> // a.k.a time.h

struct ScanContext
{
    uintmax_t packetCount;
    uintmax_t ethernetPacketCount;
    uintmax_t arpPacketCount;
    uintmax_t byteCount;
    unsigned int maxPacketLength;
    unsigned int minPacketLength;

    int isEthernet;

    struct timeval startTime;
    struct timeval endTime;

    std::map<std::string, long> packetCountPerSourceMac;
    std::map<std::string, long> packetCountPerDestMac;

    std::map<std::string, std::string> ipToMac;

    ScanContext() : packetCount(0), ethernetPacketCount(0), arpPacketCount(0), byteCount(0), maxPacketLength(0), minPacketLength(0), isEthernet(0)
    {
        memset(&this->startTime, 0, sizeof(struct timeval));
        memset(&this->endTime, 0, sizeof(struct timeval));
    }
};

#define TABLE_BITMASK 0xF
#define TABLE_SIZE    (TABLE_BITMASK+1)

static char* macToString(const unsigned char* bytes)
{
    static char mac[TABLE_SIZE][20];
    static int count = 0;

    count++;

    snprintf(mac[count & TABLE_BITMASK], 20, "%02x:%02x:%02x:%02x:%02x:%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5]);

    return mac[count & TABLE_BITMASK];
}

static char* ipv4ToString(const unsigned char* bytes)
{
    static char ip[TABLE_SIZE][16];
    static int count = 0;

    count++;

    snprintf(ip[count & TABLE_BITMASK], 16, "%u.%u.%u.%u",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3]);

    return ip[count & TABLE_BITMASK];
}

static void insertOrIncrementCounter(std::map<std::string, long> &map, std::string &key)
{
    if(map.find(key) != map.end())
    {
        map[key]++;
    }
    else
    {
        map[key] = 1;
    }
}

static std::string insertOrReplaceMac(std::map<std::string, std::string> &map, std::string &key, std::string &value)
{
    std::string tmp = "";

    if(map.find(key) != map.end())
    {
        tmp = map[key];
    }

    map[key] = value;

    return tmp;
}

static void handlePossibleEthernetPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ScanContext* ctx = (struct ScanContext*) user;

    if(ctx->packetCount == 0)
    {
        ctx->startTime = h->ts;
    }
    else
    {
        // we don't know what the last packet will be...
        ctx->endTime = h->ts;
    }

    ctx->packetCount++;

    if(h->len > ctx->maxPacketLength)
    {
        ctx->maxPacketLength = h->len;
    }

    if(ctx->minPacketLength == 0 || h->len < ctx->minPacketLength)
    {
        ctx->minPacketLength = h->len;
    }

    ctx->byteCount += h->len;

    if(ctx->isEthernet)
    {
        ctx->ethernetPacketCount++;

        if(h->caplen >= 12)
        {
            std::string sourceMacString = macToString(bytes+6);
            std::string destMacString = macToString(bytes);

            insertOrIncrementCounter(ctx->packetCountPerDestMac, destMacString);
            insertOrIncrementCounter(ctx->packetCountPerSourceMac, sourceMacString);
        }
    }
}

static void handleArpPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    ScanContext* ctx = (struct ScanContext*) user;

    ctx->arpPacketCount++;

    // 14 byte Ethernet header + 28 byte ARP header
    if(h->caplen >= 42)
    {
        // XXX check h->caplen
        uint16_t hardwareFormat;
        uint16_t protocolFormat;
        uint8_t hardwareLen;
        uint8_t protocolLen;
        uint16_t operation;
        uint8_t sourceHardware[6];
        uint8_t sourceProtocol[4];
        uint8_t targetHardware[6];
        uint8_t targetProtocol[4];
        char* senderMac = NULL;
        char* senderIp = NULL;
        char* targetMac = NULL;
        char* targetIp = NULL;

        // skip Ethernet header
        // TODO ensure 14-byte Ethernet is the only encapsulation type
        const u_char* arp_hdr = bytes + 14;

        memcpy(&hardwareFormat, arp_hdr , 2);
        memcpy(&protocolFormat, arp_hdr + 2, 2);
        hardwareFormat = htons(hardwareFormat);
        protocolFormat = htons(protocolFormat);

        hardwareLen = *(arp_hdr + 4);
        protocolLen = *(arp_hdr + 5);

        if(hardwareLen != 6)
        {
            fprintf(stderr, "[!] ARP: Unexpected hardware length\n");
            return;
        }

        if(protocolLen != 4)
        {
            fprintf(stderr, "[!] ARP: Unexpected protocol length\n");
            return;
        }

        if(protocolFormat != 0x800)
        {
            fprintf(stderr, "[!] ARP: Unexpected protocol type\n");
            return;
        }

        if(hardwareFormat != 1)
        {
            fprintf(stderr, "[!] ARP: Unexpected hardware type\n");
            return;
        }

        memcpy(&operation, arp_hdr + 6, 2);
        operation = htons(operation);

        senderMac = macToString(arp_hdr + 8);
        senderIp = ipv4ToString(arp_hdr + 14);
        targetMac = macToString(arp_hdr + 18);
        targetIp = ipv4ToString(arp_hdr + 24);

#if 0
        fprintf(stderr, "arp caplen=%d hFormat=%d pFormat=%d hLen=%d pLen=%d op=0x%04x sender(%s, %s) target(%s, %s)\n",
            h->caplen,
            hardwareFormat,
            protocolFormat,
            hardwareLen,
            protocolLen,
            operation,
            senderMac,
            senderIp,
            targetMac,
            targetIp
        );
#endif

        // Update ARP information with address of sender
        std::string senderIpString = senderIp;
        std::string senderMacString = senderMac;

        // if the sender isn't claiming it owns an IP address, don't update the table
        if(senderIpString.compare("0.0.0.0"))
        {
            std::string previous = insertOrReplaceMac(ctx->ipToMac, senderIpString, senderMacString);

            if(previous.compare("") != 0 && previous.compare(senderIp) == 0)
            {
                fprintf(stderr, "[!] %s rebound: was bound to %s\n", senderIp, previous.c_str());
            }
        }
    }
#if 0
    else
    {
        fprintf(stderr, "[!] Truncated ARP packet\n");
    }
#endif
}

static void printCountPerAddress(std::map<std::string, long> &macToCount)
{
    std::map<std::string, long>::iterator it;
    for (it = macToCount.begin();
         it != macToCount.end();
         it++)
    {
        printf("%8ld %s\n",
            it->second,
            it->first.c_str());
    }
}

static void printIpToMac(std::map<std::string, std::string> &ipToMac)
{
    std::map<std::string, std::string>::iterator it;
    for (it = ipToMac.begin();
         it != ipToMac.end();
         it++)
    {
        printf("    %-16s  %20s\n",
            it->first.c_str(),
            it->second.c_str());
    }
}

static inline const char* timevalToLocalTime(struct timeval* time)
{
    time_t unixTime = time->tv_sec;
    struct tm* localTime = localtime(&unixTime);
    char* localTimeString = asctime(localTime);

    // note: the result from asctime() has a '\n' at the end, so we truncate it
    if(localTimeString)
    {
        localTimeString[strlen(localTimeString) - 1] = '\0';
    }

    return localTimeString ? localTimeString : "?";
}

static void printStatistics(struct ScanContext* ctx)
{
    printf("%ju packets\n", ctx->packetCount);
    printf("%ju Ethernet packets\n", ctx->ethernetPacketCount);
    printf("%ju ARP packets\n", ctx->arpPacketCount);
    printf("Min size packet: %u\n", ctx->minPacketLength);
    printf("Max size packet: %u\n", ctx->maxPacketLength);

    if(0 != ctx->packetCount)
    {
        printf("Average size packet: %ju\n", ctx->byteCount / ctx->packetCount);
    }

    printf("Start time: %ju.%06ju seconds (%s)\n",
        (uintmax_t) ctx->startTime.tv_sec, (uintmax_t) ctx->startTime.tv_usec,
        timevalToLocalTime(&ctx->startTime));

    printf("End time: %ju.%06ju seconds (%s)\n",
        (uintmax_t) ctx->endTime.tv_sec, (uintmax_t) ctx->endTime.tv_usec,
        timevalToLocalTime(&ctx->endTime));

    long totalCaptureTime = ctx->endTime.tv_sec - ctx->startTime.tv_sec;
    if(0 == totalCaptureTime)
    {
        // round up to avoid divide by zero
        totalCaptureTime = 1;
    }

    printf("Total time: %ld seconds (%ld.%01ld minutes)\n",
        totalCaptureTime, totalCaptureTime / 60, totalCaptureTime % 60 * 10 / 60);

    printf("Total bytes captured: %ju bytes / %ju kilobytes / %ju megabytes\n",
        ctx->byteCount,
        ctx->byteCount / 1024,
        ctx->byteCount / 1024 / 1024);

    long kilobits = ctx->byteCount * 8 / 1024;
    long kilobitsPerSecond = kilobits / totalCaptureTime;
    printf("Overall capture speed: %ld Kbps (%ld Mbps)\n", kilobitsPerSecond, kilobitsPerSecond / 1024);

    if(!ctx->packetCountPerDestMac.empty())
    {
        printf("\nEthernet destinations:\n");
        printCountPerAddress(ctx->packetCountPerDestMac);
    }

    if(!ctx->packetCountPerSourceMac.empty())
    {
        printf("\nEthernet sources:\n");
        printCountPerAddress(ctx->packetCountPerSourceMac);
    }

    if(!ctx->ipToMac.empty())
    {
        printf("\nARP table:\n");
        printIpToMac(ctx->ipToMac);
    }
}

static int applyCaptureFilter(pcap_t* pcap, const char* filter)
{
    int result = 0;
    struct bpf_program* bpf = (struct bpf_program*) calloc(1, sizeof(struct bpf_program));

    if(NULL == bpf)
    {
        perror("calloc");
        result = -1;
        goto exit;
    }

    if(-1 == pcap_compile(pcap,
                          bpf,
                          filter,
                          1 /* optimize */,
                          PCAP_NETMASK_UNKNOWN))
    {
        // TODO: need a -v flag?
        // this error will trigger for captures with zero ARPs, for example
        //fprintf(stderr, "%s\n", pcap_geterr(pcap));
        result = -1;
        goto exit;
    }


    if(-1 == pcap_setfilter(pcap, bpf))
    {
        fprintf(stderr, "%s\n", pcap_geterr(pcap));
        result = -1;
        goto exit;
    }


exit:
    if(NULL != bpf)
    {
        pcap_freecode(bpf);
        free(bpf);
    }

    return result;
}

int main(int argc, char* argv[])
{
    int result = 0;
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct ScanContext ctx;

    if(argc < 2)
    {
        fprintf(stderr, "Not enough arguments. Please specify a pcap file.\n");
        result = 2;
        goto exit;
    }

    pcap = pcap_open_offline(argv[1], errbuf);
    if(NULL == pcap)
    {
        fprintf(stderr, "%s\n", errbuf);
        result = 3;
        goto exit;
    }

    if(DLT_EN10MB == pcap_datalink(pcap))
    {
        ctx.isEthernet = 1;
    }

    pcap_loop(pcap, -1, handlePossibleEthernetPacket, (u_char*) &ctx);

    // reopen file and check against a capture filter
    pcap_close(pcap);

    pcap = pcap_open_offline(argv[1], errbuf);
    if(NULL == pcap)
    {
        fprintf(stderr, "%s\n", errbuf);
        result = 4;
        goto exit;
    }

    if(0 != applyCaptureFilter(pcap, "arp"))
    {
        // expression could reject all packets and throw an error
        goto skip_arp;
    }
    pcap_loop(pcap, -1, handleArpPacket, (u_char*) &ctx);

skip_arp:
    pcap_close(pcap);

    // All done with packet processing.
    printStatistics(&ctx);

exit:
    return result;
}
