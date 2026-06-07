#include "PacketParser.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cctype>

using namespace std;

void PacketParser::parseFile(const char* filename)
{
    ifstream file(filename, ios::binary);

    if (!file)
    {
        cout << "PCAP file not found!" << endl;
        return;
    }

    cout << "PCAP file opened successfully!\n";

    int totalPackets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int icmpPackets = 0;

    file.seekg(24, ios::beg);

    char packetHeader[16];

    while (file.read(packetHeader, 16))
    {
        totalPackets++;

        unsigned int capturedLength =
            (unsigned char)packetHeader[8] |
            ((unsigned char)packetHeader[9] << 8) |
            ((unsigned char)packetHeader[10] << 16) |
            ((unsigned char)packetHeader[11] << 24);

        cout << "\n========================\n";
        cout << "Packet #" << totalPackets << endl;
        cout << "Captured Length: "
             << capturedLength << endl;

        char* packetData = new char[capturedLength];

        file.read(packetData, capturedLength);

        if (!file)
        {
            delete[] packetData;
            break;
        }

        unsigned char* ethernet =
            (unsigned char*)packetData;

        unsigned short etherType =
            (ethernet[12] << 8) |
            ethernet[13];

        cout << "EtherType: 0x"
             << hex << etherType
             << dec << endl;

        if (etherType == 0x0800)
        {
            unsigned char* ip =
                ethernet + 14;

            int ipHeaderLength =
                (ip[0] & 0x0F) * 4;

            unsigned char protocol =
                ip[9];

            if (protocol == 6)
            {
                tcpPackets++;

                unsigned char* tcp =
                    ip + ipHeaderLength;

                unsigned short srcPort =
                    (tcp[0] << 8) | tcp[1];

                unsigned short dstPort =
                    (tcp[2] << 8) | tcp[3];

                cout << "TCP Source Port: "
                     << srcPort << endl;

                cout << "TCP Dest Port: "
                     << dstPort << endl;
            }
            else if (protocol == 17)
            {
                udpPackets++;
            }
            else if (protocol == 1)
            {
                icmpPackets++;
            }
        }

        delete[] packetData;
    }

    cout << "\n========================\n";
    cout << "PACKET STATISTICS\n";
    cout << "========================\n";

    cout << "Total Packets : "
         << totalPackets << endl;

    cout << "TCP Packets : "
         << tcpPackets << endl;

    cout << "UDP Packets : "
         << udpPackets << endl;

    cout << "ICMP Packets : "
         << icmpPackets << endl;

    file.close();
}//test