
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

#include "des.h"
using CryptoPP::DES;

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

    string plain = "Attack CBC Mode Test";
    cout << "plaintext: " << plain << endl; //  std::getline(std::cin, plain);

    string keystring;
    cout << "Input 8 bytes key: ";
    getline(std::cin, keystring);

    if (keystring.length() != DES::DEFAULT_KEYLENGTH)
    {
        cout << "Wrong key length input. Key length must be 8 bytes!\n";
        return -1;
    }

    SecByteBlock key(DES::DEFAULT_KEYLENGTH);

    // Do something with the key


    string iv_input;
    byte *iv = new byte[DES::BLOCKSIZE];

	do
	{
		cout << "Input iv: ";
		// flush all buffer before getline
		fflush(stdin);
		std::getline(cin, iv_input);

		if (iv_input.length() != DES::BLOCKSIZE)
		{
			cout << "Wrong iv length input. iv length must be 8 bytes!\n";
		}
		else
		{
			break;
		}
	} while (1);

    string cipher, recovered;

    CBC_Mode<DES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain, true,
                 new StreamTransformationFilter(e,
                                                new StringSink(cipher)) // StreamTransformationFilter
    );                                                                  // StringSource

    CBC_Mode<DES>::Encryption e2;
    e2.SetKeyWithIV(key, key.size(), iv);
    StringSource (eIV, true,
                    new StreamTransformationFilter(e2,
                        new StringSink(plaintext))
                        );
    cout << "Attack cipher text: " << plaintext << endl;


    // Decrypt
    CBC_Mode<DES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(recovered)) // StreamTransformationFilter
    );

    cout << "Recovered text: " << recovered << endl;

    return 0;
}