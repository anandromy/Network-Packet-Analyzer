#include "PacketParser.h"
#include <iostream>
#include <string>
using namespace std;

int main(int argc, char* argv[])
{
    PacketParser parser;

    if (argc == 3 && string(argv[1]) == "-f"){
        parser.parseFile(argv[2]);  
    }else if (argc == 3 && string(argv[1]) == "-i"){
        parser.parseLive(argv[2]); 
    }else if (argc == 2 && string(argv[1]) == "-l"){
        parser.parseLive(nullptr);
    }else {
        cout << "Usage:\n"
             << "  ./parser -f <file.pcap>   — file mode\n"
             << "  ./parser -i <eth0>        — live on interface\n"
             << "  ./parser -l               — live, auto-pick\n";
    }
    return 0;
}