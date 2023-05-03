
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;
#include <bits/stdc++.h>

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::byte;
using CryptoPP::SecByteBlock;
#include <string.h>
#include "misc.h"
#include <initializer_list>
#include <vector>
#include "filters.h"

int main()
{
    AutoSeededRandomPool prng;

    string plain = "Attack AES Mode Test";
    cout << "plaintext: " << plain << endl; //  std::getline(std::cin, plain);

    string keystring;
    cout << "Input 16 bytes key: ";
	fflush(stdin);
    getline(std::cin, keystring);
    if (keystring.length() != AES::DEFAULT_KEYLENGTH)
    {
        cout << "Wrong key length input. Key length must be 16 bytes!\n";
        return -1;
    }

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);

    // Do something with the key

    string iv_input;
    byte *iv = new byte[AES::BLOCKSIZE];

    do
    {
        cout << "Input 16 bytes iv: ";
        // flush all buffer before getline
        fflush(stdin);
        std::getline(std::cin, iv_input);

        if (iv_input.length() != AES::BLOCKSIZE)
        {
            cout << "Wrong iv length input. iv length must be 16 bytes!\n";
        }
        else
        {
            break;
        }
    } while (1);

    string cipher, recovered, encoded;

    // convert key
    encoded.clear();
    StringSource(key, key.size(), true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource

    string encodedKey(encoded.begin(), encoded.end());
    cout << "key: " << encodedKey << endl;

    // convert iv
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                     new StringSink(encoded)) // HexEncoder
    );                                        // StringSource
    string encodedIV(encoded.begin(), encoded.end());
    cout << "iv: " << encodedIV << endl;
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)) // StreamTransformationFilter
    );                                                                  // StringSource

    cout << "cipher text: " << cipher << endl;

    // eP1: Plaintext from eavesdropper , eC1: Cipher from eavesdropper
    string eP1 = "Attack CBC Mode", eC1 = "5Q88";
    // Create e2 because e properties (key, iv) will be changed after e is used.
    CBC_Mode<AES>::Encryption e2;
    e2.SetKeyWithIV(key, key.size(), iv);
    StringSource(eP1, true,
                 new StreamTransformationFilter(e2,
                                                new StringSink(eC1)));
    cout << "Attack cipher text: " << eC1 << endl;
    // Decrypt
    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(recovered)) // StreamTransformationFilter
    );

    cout << "Recovered text: " << recovered << endl;

    return 0;
}