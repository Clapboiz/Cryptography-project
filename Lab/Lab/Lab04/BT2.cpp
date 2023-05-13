#include <iostream>
#include <string>
#include "cryptlib.h"
#include "filters.h"
#include "md5.h"
#include "sha3.h"
#include "sha.h"
#include "shake.h"
#include "hex.h"

using namespace std;
using namespace CryptoPP;

void sha1(string input, string& digest) {
    SHA1 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha256(string input, string& digest) {
    SHA256 hash;
    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

int main(int argc, char* argv[])
{
   string d1, d2;
   
   sha1("Yoda said, Do or do not. There is no try.", d1);

   cout << "message: Yoda said, Do or do not. There is no try. " << endl << d1 << std::endl;

   sha256("Yoda said, Do or do not. There is no try.", d2 );
   
   cout << "message: Yoda said, Do or do not. There is no try. " << endl << d2 << std::endl;
   
    return 0;
}

