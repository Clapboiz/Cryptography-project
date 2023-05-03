// #include "stdafx.h"

#include <rsa.h>
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <sha.h>
using CryptoPP::SHA1;

#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <locale>
using std::wstring_convert;

#include <codecvt>
using std::codecvt_utf8;

#include <hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <integer.h>
using CryptoPP::Integer;
#include <string>
using std::string;
using std::wstring;
#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 1024 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        //Plain text input
        string plain="RSA Encryption Schemes", recovered, cipher;
        cout << "Plain Text : " << plain << endl;

        // Generated Parameters
        const Integer n = parameters.GetModulus();
        const Integer p = parameters.GetPrime1();
        const Integer q = parameters.GetPrime2();
        const Integer d = parameters.GetPrivateExponent();
        const Integer e = parameters.GetPublicExponent();

        // Dump
        cout << "RSA Parameters:" << endl;
        cout << " n: " << n << endl;
        cout << " p: " << p << endl;
        cout << " q: " << q << endl;
        cout << " d: " << d << endl;
        cout << " e: " << e << endl;
        cout << endl;

         // Encryption
        RSAES_OAEP_SHA_Encryptor enc( publicKey );
        
        StringSource( plain, true,
            new PK_EncryptorFilter( rng, enc,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        cout << "Cipher Text : " <<ToHex(cipher)<< endl;

        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, dec,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        assert( plain == recovered );
        cout << "Recovered Text : " <<plain << endl;
    }

         catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }

    system ("pause");
    return 0;
}