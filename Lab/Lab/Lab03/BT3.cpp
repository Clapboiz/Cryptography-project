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

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
using std::cin;

#include <filters.h>

#include <assert.h>

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey );


int main(int argc, char* argv[])
{
    try
    {
        AutoSeededRandomPool rng;
        
        // Load private key
        RSA::PrivateKey privateKey;
        LoadKey("privateKey.der", privateKey);

        //Input Ciphertext
        std::ifstream file("cipherText.txt", std::ios::binary);

        // Get the length of the ciphertext
        file.seekg(0, std::ios::end);
        size_t ciphertextLen = file.tellg();
        file.seekg(0, std::ios::beg);

        // Allocate memory for the ciphertext
        CryptoPP::byte* ciphertext = new CryptoPP::byte[ciphertextLen];

        // Read the ciphertext from the file
        file.read(reinterpret_cast<char*>(ciphertext), ciphertextLen);

        // Close the file
        file.close();

        // Decrypt
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );       

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( ciphertextLen );
        SecByteBlock recovered( dpl );

        // Paydirt
        DecodingResult result = decryptor.Decrypt( rng,
            ciphertext, ciphertextLen, recovered );

        // SecByteBlock is overloaded for proper results 
        string revocered_text = string(reinterpret_cast<const char*>(recovered.data()), result.messageLength);
        cout << "Recovered plaintext: " << revocered_text << endl;
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
