#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#include <string>
#include <map>
#include <iterator>

struct scan_ctx
{
    long count;
    int maxlen;
    int minlen;
    std::map<std::string, long> countPerSourceMac;
    std::map<std::string, long> countPerDestMac;

    scan_ctx() : count(0), maxlen(0), minlen(0) { }
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
    scan_ctx* ctx = (struct scan_ctx*) user;

    // update counters
    ctx->count++;
    if(h->len > ctx->maxlen) ctx->maxlen = h->len;
    if(ctx->minlen == 0 || h->len < ctx->minlen) ctx->minlen = h->len;

    // update per-mac-address counter
    std::string sourceMacString = macToString(bytes);
    std::string destMacString = macToString(bytes+6);

    // -- Verbose flag?
    //printf("%s, %s\n", sourceMac, destMac);

    insertOrIncrementCounter(ctx->countPerDestMac, destMacString);
    insertOrIncrementCounter(ctx->countPerSourceMac, sourceMacString);
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

static void printStatistics(struct scan_ctx* ctx)
{
    printf("%ld packets\n", ctx->count);
    printf("Max size packet: %d\n", ctx->maxlen);
    printf("Min size packet: %d\n", ctx->minlen);

    printf("Ethernet destinations:\n");
    printCountPerAddress(ctx->countPerDestMac);

    printf("\nEthernet sources:\n");
    printCountPerAddress(ctx->countPerSourceMac);
}


int main(int argc, char* argv[])
{
    int result = 0;
    pcap_t* pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct scan_ctx ctx;

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
