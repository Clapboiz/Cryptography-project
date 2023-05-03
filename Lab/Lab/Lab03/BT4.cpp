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
using std::wcin;
using std::wcout;
using std::wcerr;

#include <assert.h>

wstring string_to_wstring(const std::string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string(const std::wstring &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

string InputFromScreen()
{
    wstring wplain;
    wcout << "Input text: ";
    getline(wcin, wplain);
    return wstring_to_string(wplain);
}

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "");
    try
    {
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 1024 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain, cipher, recovered;
        plain = InputFromScreen();
        wcout << L"Plain Text : " << string_to_wstring(plain) << endl;

        // Encryption
        RSAES_OAEP_SHA_Encryptor enc( publicKey );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, enc,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource
        wcout << L"Cipher Text : " << string_to_wstring(ToHex(cipher)) << endl;

        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, dec,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        assert( plain == recovered );
        wcout << L"Recovered Text : " << string_to_wstring(recovered) << endl;
    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }

    system ("pause");
	return 0;
}

