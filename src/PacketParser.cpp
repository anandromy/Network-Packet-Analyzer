#include "PacketParser.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <csignal>
using namespace std;

// handling exit. 
static pcap_t* g_handle = nullptr;
static Stats   g_stats;

static void sigHandler(int) {
    if (g_handle) pcap_breakloop(g_handle);
}

// packet parser that takes works for both the modes. 
void PacketParser::parsePacket(const unsigned char* pkt,unsigned int len, Stats& stats) {

    stats.total++;
    cout << "\n========================\n";
    cout << "Packet #" << stats.total << "\n";
    cout << "Captured Length: " << len << "\n";

    if (len < 14) { cout << "Too short for Ethernet\n"; return; }

    unsigned short etherType = (pkt[12] << 8) | pkt[13];
    cout << "EtherType: 0x" << hex << etherType << dec << "\n";

    if (etherType != 0x0800) return;
    if (len < 34)            return;

    const unsigned char* ip = pkt + 14;
    unsigned int ipHLen     = (ip[0] & 0x0F) * 4;
    unsigned char proto     = ip[9];

    if (proto == 6 && len >= 14u + ipHLen + 4u) {
        stats.tcp++;
        const unsigned char* tcp = ip + ipHLen;
        cout << "Protocol: TCP\n";
        cout << "Src Port: " << ((tcp[0] << 8) | tcp[1]) << "\n";
        cout << "Dst Port: " << ((tcp[2] << 8) | tcp[3]) << "\n";
    }
    else if (proto == 17 && len >= 14u + ipHLen + 4u) {
        stats.udp++;
        const unsigned char* udp = ip + ipHLen;
        cout << "Protocol: UDP\n";
        cout << "Src Port: " << ((udp[0] << 8) | udp[1]) << "\n";
        cout << "Dst Port: " << ((udp[2] << 8) | udp[3]) << "\n";
    }
    else if (proto == 1) {
        stats.icmp++;
        cout << "Protocol: ICMP\n";
    }
}

// custom printer
static void printStats(const Stats& s) {
    cout << "\n========================\n";
    cout << "PACKET STATISTICS\n";
    cout << "========================\n";
    cout << "Total : " << s.total << "\n";
    cout << "TCP   : " << s.tcp   << "\n";
    cout << "UDP   : " << s.udp   << "\n";
    cout << "ICMP  : " << s.icmp  << "\n";
}

// file mode
void PacketParser::parseFile(const char* filename)
{
    ifstream file(filename, ios::binary);
    if (!file) 
    { 
        cout << "PCAP file not found!" << endl; 
        return; 
    }

    uint32_t signature;
    file.read(reinterpret_cast<char*>(&signature), 4);

    if (signature != 0xA1B2C3D4) { 
        cout << "Not a valid PCAP file!\n"; 
        return; 
    }

    cout << "PCAP File opened successfully!\n";
    file.seekg(24, ios::beg);

    char packetHeader[16];
    Stats stats; 
    while (file.read(packetHeader, 16)) {
        unsigned int capturedLength =
            (unsigned char)packetHeader[8] |
            ((unsigned char)packetHeader[9]  << 8) |
            ((unsigned char)packetHeader[10] << 16) |
            ((unsigned char)packetHeader[11] << 24);

        vector<unsigned char> buf(capturedLength);

        if (!file.read(reinterpret_cast<char*>(buf.data()), capturedLength)){
            break;
        }
        parsePacket(buf.data(), capturedLength, stats);
    }
    printStats(stats);
}

// live mode
void PacketParser::packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    Stats* stats = reinterpret_cast<Stats*>(userData);
    parsePacket(packet, pkthdr->caplen, *stats);
}

void PacketParser::parseLive(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    string selected;

    // auto picking when null pointer is received
    if (!device) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            cout << "No devices found — run with sudo/admin.\n";
            return;
        }
        cout << "Available interfaces:\n";
        int i = 1;
        for (auto* d = alldevs; d; d = d->next)
            cout << "  " << i++ << ". " << d->name << "\n";
        selected = alldevs->name;
        pcap_freealldevs(alldevs);
        device = selected.c_str();
        cout << "Auto-selected: " << device << "\n";
    }

    g_handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (!g_handle) {
        cout << "Could not open " << device << ": " << errbuf << "\n";
        return;
    }

    signal(SIGINT, sigHandler);
    cout << "Live capture on [" << device << "] — Ctrl+C to stop\n";

    pcap_loop(g_handle, 0, packetHandler, reinterpret_cast<unsigned char*>(&g_stats));

    printStats(g_stats);
    pcap_close(g_handle);
    g_handle = nullptr;
}