#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <inttypes.h>

#include <string>
#include <map>
#include <iterator>
#include <ctime> // a.k.a time.h

struct ScanContext
{
    uint64_t packetCount;
    uint64_t byteCount;
    uint32_t maxPacketLength;
    uint32_t minPacketLength;

    struct timeval startTime;
    struct timeval endTime;

    std::map<std::string, long> packetCountPerSourceMac;
    std::map<std::string, long> packetCountPerDestMac;

    ScanContext() : packetCount(0), byteCount(0), maxPacketLength(0), minPacketLength(0)
    {
        memset(&this->startTime, 0, sizeof(struct timeval));
        memset(&this->endTime, 0, sizeof(struct timeval));
    }
};

static char* macToString(const unsigned char* bytes)
{
    static char mac[18];
    snprintf(mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             bytes[0],
             bytes[1],
             bytes[2],
             bytes[3],
             bytes[4],
             bytes[5]);

    return mac;
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

static void handlePacket(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
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


    if(h->caplen >= 12)
    {
        std::string sourceMacString = macToString(bytes+6);
        std::string destMacString = macToString(bytes);

        insertOrIncrementCounter(ctx->packetCountPerDestMac, destMacString);
        insertOrIncrementCounter(ctx->packetCountPerSourceMac, sourceMacString);
    }
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

static void printStatistics(struct ScanContext* ctx)
{
    printf("%lld packets\n", ctx->packetCount);
    printf("Max size packet: %d\n", ctx->maxPacketLength);
    printf("Min size packet: %d\n", ctx->minPacketLength);

    // note: the result from asctime() has a '\n' at the end, so we truncate it
    char* localTimeString;

    time_t startTime = ctx->startTime.tv_sec;
    struct tm* startLocalTime = localtime(&startTime);
    localTimeString = asctime(startLocalTime);
    if(localTimeString) localTimeString[strlen(localTimeString) - 1] = '\0';
    printf("Start time: %ld.%06d seconds (%s)\n",
        ctx->startTime.tv_sec, ctx->startTime.tv_usec,
        localTimeString ? localTimeString : "?");

    time_t endTime = ctx->endTime.tv_sec;
    struct tm* endLocalTime = localtime(&endTime);
    localTimeString = asctime(startLocalTime);
    if(localTimeString) localTimeString[strlen(localTimeString) - 1] = '\0';
    printf("End time: %ld.%06d seconds (%s)\n",
        ctx->endTime.tv_sec, ctx->endTime.tv_usec,
        localTimeString ? localTimeString : "?");

    long totalCaptureTime = ctx->endTime.tv_sec - ctx->startTime.tv_sec;
    printf("Total time: %ld seconds (%ld.%01ld minutes)\n",
        totalCaptureTime, totalCaptureTime / 60, totalCaptureTime % 60 * 10 / 60);

    printf("Total bytes captured: %lld bytes / %lld kilobytes / %lld megabytes\n",
        ctx->byteCount,
        ctx->byteCount / 1024,
        ctx->byteCount / 1024 / 1024);

    long kilobits = ctx->byteCount * 8 / 1024;
    long kilobitsPerSecond = kilobits / totalCaptureTime;
    printf("Overall capture speed: %ld Kbps (%ld Mbps)\n", kilobitsPerSecond, kilobitsPerSecond / 1024);

    printf("\nEthernet destinations:\n");
    printCountPerAddress(ctx->packetCountPerDestMac);

    printf("\nEthernet sources:\n");
    printCountPerAddress(ctx->packetCountPerSourceMac);
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

    pcap_loop(pcap, -1, handlePacket, (u_char*) &ctx);

    printStatistics(&ctx);

exit:
    return result;
}
