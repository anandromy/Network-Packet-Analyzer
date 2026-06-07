#include "PacketParser.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <csignal>
using namespace std;

// ── Globals for Ctrl+C handling ──────────────────────────────────
static pcap_t* g_handle = nullptr;
static Stats   g_stats;

static void sigHandler(int) {
    if (g_handle) pcap_breakloop(g_handle);
}

// ── JSON output helpers ───────────────────────────────────────────
static void emitPacket(const Stats& s, unsigned int len,
                       const string& proto,
                       int src = -1, int dst = -1)
{
    cout << "{\"type\":\"packet\""
         << ",\"num\":"   << s.total
         << ",\"len\":"   << len
         << ",\"proto\":\"" << proto << "\"";
    if (src >= 0) cout << ",\"src\":" << src << ",\"dst\":" << dst;
    cout << "}\n";
    cout.flush();
}

static void emitStatus(const string& msg) {
    cout << "{\"type\":\"status\",\"msg\":\"" << msg << "\"}\n";
    cout.flush();
}

static void emitStats(const Stats& s) {
    cout << "{\"type\":\"stats\""
         << ",\"total\":" << s.total
         << ",\"tcp\":"   << s.tcp
         << ",\"udp\":"   << s.udp
         << ",\"icmp\":"  << s.icmp
         << "}\n";
    cout.flush();
}

// ── Core packet parser (shared by file + live) ───────────────────
void PacketParser::parsePacket(const unsigned char* pkt,
                                unsigned int len, Stats& stats)
{
    stats.total++;

    if (len < 14) {
        emitPacket(stats, len, "SHORT");
        return;
    }

    unsigned short etherType = (pkt[12] << 8) | pkt[13];
    if (etherType != 0x0800) {
        emitPacket(stats, len, "OTHER");
        return;
    }

    if (len < 34) { emitPacket(stats, len, "OTHER"); return; }

    const unsigned char* ip = pkt + 14;
    unsigned int ipHLen     = (ip[0] & 0x0F) * 4;
    unsigned char proto     = ip[9];

    if (proto == 6 && len >= 14u + ipHLen + 4u) {
        stats.tcp++;
        const unsigned char* tcp = ip + ipHLen;
        int src = (tcp[0] << 8) | tcp[1];
        int dst = (tcp[2] << 8) | tcp[3];
        emitPacket(stats, len, "TCP", src, dst);
    }
    else if (proto == 17 && len >= 14u + ipHLen + 4u) {
        stats.udp++;
        const unsigned char* udp = ip + ipHLen;
        int src = (udp[0] << 8) | udp[1];
        int dst = (udp[2] << 8) | udp[3];
        emitPacket(stats, len, "UDP", src, dst);
    }
    else if (proto == 1) {
        stats.icmp++;
        emitPacket(stats, len, "ICMP");
    }
    else {
        emitPacket(stats, len, "OTHER");
    }
}

// ── pcap_loop callback ───────────────────────────────────────────
void PacketParser::packetHandler(unsigned char* userData,
                                  const struct pcap_pkthdr* pkthdr,
                                  const unsigned char* packet)
{
    Stats* stats = reinterpret_cast<Stats*>(userData);
    parsePacket(packet, pkthdr->caplen, *stats);
}

// ── File mode ────────────────────────────────────────────────────
void PacketParser::parseFile(const char* filename)
{
    ifstream file(filename, ios::binary);
    if (!file) { emitStatus("PCAP file not found!"); return; }

    uint32_t signature;
    file.read(reinterpret_cast<char*>(&signature), 4);
    if (signature != 0xA1B2C3D4) { emitStatus("Not a valid PCAP file!"); return; }

    emitStatus("File opened successfully");
    file.seekg(24, ios::beg);

    Stats stats;
    char packetHeader[16];
    while (file.read(packetHeader, 16)) {
        unsigned int capturedLength =
            (unsigned char)packetHeader[8]        |
            ((unsigned char)packetHeader[9]  << 8) |
            ((unsigned char)packetHeader[10] << 16)|
            ((unsigned char)packetHeader[11] << 24);

        vector<unsigned char> buf(capturedLength);
        if (!file.read(reinterpret_cast<char*>(buf.data()), capturedLength)) break;
        parsePacket(buf.data(), capturedLength, stats);
    }
    emitStats(stats);
}

// ── Live mode ────────────────────────────────────────────────────
void PacketParser::parseLive(const char* device)
{
    g_stats = Stats{};
    char errbuf[PCAP_ERRBUF_SIZE];
    string selected;

    if (!device) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            emitStatus("No devices found — run with sudo.");
            return;
        }
        // Emit available interfaces as JSON
        cout << "{\"type\":\"interfaces\",\"list\":[";
        int i = 0;
        for (auto* d = alldevs; d; d = d->next) {
            if (i++) cout << ",";
            cout << "\"" << d->name << "\"";
        }
        cout << "]}\n";
        cout.flush();

        selected = alldevs->name;
        pcap_freealldevs(alldevs);
        device = selected.c_str();
    }

    g_handle = pcap_open_live(device, 65535, 1, 1000, errbuf);
    if (!g_handle) {
        emitStatus(string("Could not open ") + device + ": " + errbuf);
        return;
    }

    signal(SIGINT, sigHandler);
    emitStatus(string("Capturing on ") + device);

    pcap_loop(g_handle, 0, packetHandler,
              reinterpret_cast<unsigned char*>(&g_stats));

    emitStats(g_stats);
    pcap_close(g_handle);
    g_handle = nullptr;
}