#include <rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;


#include <pssr.h>
using CryptoPP::PSS;

#include <sha.h>
using CryptoPP::SHA1;
using CryptoPP::SHA256;
#include <filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <files.h>
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <secblock.h>
using CryptoPP::SecByteBlock;
using CryptoPP::byte;

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
#include <iomanip>
using std::hex;
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

void PrintByte(const SecByteBlock &message)
{
    string encoded;
    StringSource(message, message.size(), true, new HexEncoder(new StringSink(encoded)));
    cout << encoded << endl;
}

int main(int argc, char* argv[])
{
    try
    {
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 3072);

        RSA::PrivateKey privateKey(parameters);
        RSA::PublicKey publicKey(parameters);

        // Message
        string message = "RSA Authentication";
        cout << "Message : " << message << endl;
        // Signer object
        RSASS<PSS, SHA256>::Signer signer(privateKey);

        // Create signature space
        size_t length = signer.MaxSignatureLength();
        SecByteBlock signature(length);

        // Sign message
        length = signer.SignMessage(rng, (const byte*) message.c_str(),
            message.length(), signature);

        // Resize now we know the true size of the signature
        signature.resize(length);
        cout << "Signature : "; 
        PrintByte(signature);
        // Verifier object
        RSASS<PSS, SHA256>::Verifier verifier(publicKey);

        // Verify
        bool result = verifier.VerifyMessage((const byte*)message.c_str(),
            message.length(), signature, signature.size());

        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( privateKey );
        string recovered;
        StringSource( signature, true,
            new PK_DecryptorFilter( rng, dec,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        assert( message == recovered );
        cout << "Recovered Text : " <<message << endl;

        // Result
        if(true == result) {
            cout << "Signature on message verified" << endl;
            
        } else {
            cout << "Message verification failed" << endl;
        }
    } // try

    catch( CryptoPP::Exception& e ) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    system ("pause");
    return 0;
}