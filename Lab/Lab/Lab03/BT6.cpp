// Sample.cpp
//

//#include "stdafx.h"

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA1;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::cin;
using std::getline;

#include <assert.h>
void LoadKey( const string& filename, RSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}


int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        //InvertibleRSAFunction parameters;
        //parameters.GenerateRandomWithKeySize( rng, 1024 );

        RSA::PrivateKey privateKey;
        LoadKey("private_key.bin", privateKey);
        RSA::PublicKey publicKey;
        LoadKey("public_key.bin", publicKey);

        ////////////////////////////////////////////////
        // Secret to protect
        string input;
        cout << "Input plain text: ";
        getline(cin, input);
        SecByteBlock plaintext((const CryptoPP::byte*) input.data(), input.size());

        ////////////////////////////////////////////////
        // Encrypt
        RSAES_OAEP_SHA_Encryptor encryptor( publicKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != encryptor.FixedMaxPlaintextLength() );
        assert( SECRET_SIZE <= encryptor.FixedMaxPlaintextLength() );        

        // Create cipher text space
        size_t ecl = encryptor.CiphertextLength( plaintext.size() );
        assert( 0 != ecl );
        SecByteBlock ciphertext( ecl );

        // Paydirt
        encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );

        ////////////////////////////////////////////////
        // Decrypt
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != decryptor.FixedCiphertextLength() );
        assert( ciphertext.size() <= decryptor.FixedCiphertextLength() );        

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
        assert( 0 != dpl );
        SecByteBlock recovered( dpl );

        // Paydirt
        DecodingResult result = decryptor.Decrypt( rng,
            ciphertext, ciphertext.size(), recovered );

        // More sanity checks
        assert( result.isValidCoding );        
        assert( result.messageLength <=
            decryptor.MaxPlaintextLength( ciphertext.size() ) );
        assert( plaintext.size() == result.messageLength );

        // At this point, we can set the size of the recovered
        //  data. Until decryption occurs (successfully), we
        //  only know its maximum size
        recovered.resize( result.messageLength );

        // SecByteBlock is overloaded for proper results below
        assert( plaintext == recovered );
        cout << "Ciphertext: ";
        for (size_t i = 0; i < ciphertext.size(); i++) {
            cout << std::hex << (int)ciphertext[i];
        }
        cout << endl;
        cout << "Recovered plain text: " << string(reinterpret_cast<const char*>(recovered.data()), recovered.size()) << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

    system ("pause");    
	return 0;
}


void SaveKey( const RSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

