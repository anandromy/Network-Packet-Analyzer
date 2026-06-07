#ifndef PACKETPARSER_H
#define PACKETPARSER_H

#include <pcap.h>

struct Stats {
    int total = 0, tcp = 0, udp = 0, icmp = 0;
};

class PacketParser
{
public:
    void parseFile(const char* filename);
    void parseLive(const char* device);   //we can pass null pointer to auto-pick

private:
    static void parsePacket(const unsigned char* pkt, unsigned int len, Stats& stats);
    static void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet);
};

#endif