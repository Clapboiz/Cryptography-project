#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

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

#include "ccm.h"
using CryptoPP::ECB_Mode;
#include "assert.h"

int main(int argc, char *argv[])
{
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	string plain;
	cout << "Enter plain(ECB Mode): ";
	std::getline(std::cin, plain);
	string cipher, encoded, recovered;

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "key: " << encoded << endl;

	cout << "plain text: " << plain << endl;

	ECB_Mode<AES>::Encryption e;
	e.SetKey(key, sizeof(key));

	StringSource(plain, true,
				 new StreamTransformationFilter(e,
												new StringSink(cipher)) // StreamTransformationFilter
	);																	// StringSource

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
				 new HexEncoder(
					 new StringSink(encoded)) // HexEncoder
	);										  // StringSource
	cout << "cipher text: " << encoded << endl;

	ECB_Mode<AES>::Decryption d;
	d.SetKey(key, sizeof(key));

	// The StreamTransformationFilter removes
	//  padding as required.
	StringSource(cipher, true,
				 new StreamTransformationFilter(d,
												new StringSink(recovered)) // StreamTransformationFilter
	);																	   // StringSource

	cout << "recovered text: " << recovered << endl;
	system("pause");
	return 0;
}
