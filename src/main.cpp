#include "PacketParser.h"

int main()
{
    PacketParser parser;
    parser.parseFile("samples/sample.pcap");

    return 0;
}