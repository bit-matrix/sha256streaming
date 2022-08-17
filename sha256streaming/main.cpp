//
//  main.cpp
//  sha256context
//
//  Created by Burak on 16.08.2022.
//

#include <iostream>
#include "sha256.h"
#include <sstream>
#include "Bytestring.hpp"

std::string sha256finalize(std::string in1, std::string in2) {
    
    ByteString bs(in1);
    std::string s1 = bs.fromHexString();
    
    std::vector<unsigned char> t1;
    t1.insert(t1.begin(), s1.begin(), s1.end());
    
    ByteString bs2(in2);
    std::string s2 = bs2.fromHexString();
    const unsigned char* t2 = reinterpret_cast<const unsigned char*>(s2.c_str());
    
    CSHA256 cs;
    
    cs.Load(t1);
    cs.SafeWrite(t2,s2.size());
    
    std::vector<unsigned char> result(32);
    
    cs.Finalize(result.data());
    
    std::string string;

    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    for( int i = 0; i < result.size(); ++i )
    {
        char const byte = result[i];

        string += hex_chars[ ( byte & 0xF0 ) >> 4 ];
        string += hex_chars[ ( byte & 0x0F ) >> 0 ];
    }
    
    return string;
}

std::string sha256update(std::string in1, std::string in2) {
    
    ByteString bs(in1);
    std::string s1 = bs.fromHexString();
    
    std::vector<unsigned char> t1;
    t1.insert(t1.begin(), s1.begin(), s1.end());

    ByteString bs2(in2);
    std::string s2 = bs2.fromHexString();
    const unsigned char* t2 = reinterpret_cast<const unsigned char*>(s2.c_str());
    
    CSHA256 cs;
    
    cs.Load(t1);
    cs.SafeWrite(t2,s2.size());
    
    std::vector<unsigned char> l;
    l = cs.Save();

    std::string string;

    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    for( int i = 0; i < l.size(); ++i )
    {
        char const byte = l[i];

        string += hex_chars[ ( byte & 0xF0 ) >> 4 ];
        string += hex_chars[ ( byte & 0x0F ) >> 0 ];
    }

    return string;
}


std::string sha256initialize(std::string in) {
    
    ByteString bs(in);
    std::string s = bs.fromHexString();
    
    const unsigned char* t = reinterpret_cast<const unsigned char*>(s.c_str());

    CSHA256 cs;
    cs.SafeWrite(t, s.size());

    std::vector<unsigned char> l;
    l = cs.Save();

    std::string string;

    char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    for( int i = 0; i < l.size(); ++i )
    {
        char const byte = l[i];

        string += hex_chars[ ( byte & 0xF0 ) >> 4 ];
        string += hex_chars[ ( byte & 0x0F ) >> 0 ];
    }

    return string;
}

int main() {
    std::cout << "1.\t" << "OP_SHA256INITIALIZE" << std::endl;
    std::cout << "2.\t" << "OP_SHA256UPDATE" << std::endl;
    std::cout << "3.\t" << "OP_SHA256FINALIZE" << std::endl;
    std::cout << "Option selection > " << std::flush;
    int selection;
    std::cin >> selection;
    
    switch (selection) {
        case 1:
        {
            std::cout << "Enter data for SHA256 context > " << std::flush;
            std::string dataForContext;
            std::cin >> dataForContext;
            std::cout << "SHA256 context is:" << std::endl;
            std::cout << sha256initialize(dataForContext) << std::endl;
            break;
        }

        case 2:
        {
            std::cout << "Enter previous SHA256 context > " << std::flush;
            std::string prev256context;
            std::cin >> prev256context;
            
            std::cout << "Enter new data for SHA256 context > " << std::flush;
            std::string newDataForContext;
            std::cin >> newDataForContext;
            
            std::cout << "Updated SHA256 context is:" << std::endl;
            std::cout << sha256update(prev256context, newDataForContext) << std::endl;
            
            break;
        }
            
        case 3:
        {
            std::cout << "Enter previous SHA256 context > " << std::flush;
            std::string prev256context;
            std::cin >> prev256context;
            
            std::cout << "Enter new data for SHA256 context > " << std::flush;
            std::string newDataForContext;
            std::cin >> newDataForContext;
            
            std::cout << "SHA256 hash is:" << std::endl;
            std::cout << sha256finalize(prev256context, newDataForContext) << std::endl;
            
            break;
        }
            
        default:
            std::cout << "Invalid option." << std::endl;
            break;
    }
    
    
    
   // std::cout << "Enter data for SHA256 context > " << std::flush;
    // std::string input;
    //std::cin >> input;
    //std::cout << "SHA256 context is:" << std::endl;
    //std::cout << sha256context(input) << std::endl;
    return 0;
}
