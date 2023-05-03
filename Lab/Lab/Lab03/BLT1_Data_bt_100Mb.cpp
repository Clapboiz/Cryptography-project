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

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <ctime>
#include "hrtimer.h"

#include <string>
using std::string;
using std::wstring;

#include <locale>
using std::wstring_convert;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::wcout;
using std::cerr;
using std::endl;
using std::wcin;
using std::getline;

#include <fcntl.h> //_O_WTEXT
#include <io.h> //_setmode()
#include <assert.h>
#include <iomanip>
#include <codecvt>
#include <fstream>

// convert UTF-16 string to wstring
wstring utf16_to_wstring(const string &str) {
  using convert_type = std::codecvt_utf16<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.from_bytes(str);
}

// convert wstring to UTF-16 string
string wstring_to_utf16(const wstring &wstr) {
  using convert_type = std::codecvt_utf16<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.to_bytes(wstr);
}

string ToHex(const string &text)
{
    string encoded;
    encoded.clear();
    StringSource(text, true, new HexEncoder(new StringSink(encoded))); // HexEncoder
    return encoded;
}

const double runTimeInSeconds = 3.0;
const double cpuFreq = 3.3 * 1000 * 1000 * 1000;

void encryptionTime()
{
   #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

 try
    {
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 16384 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string plain, cipher, recovered;
        // wcout << L"Plain Text : ";
        // wstring wplain;
        // getline(wcin, wplain);

        // plain = wstring_to_utf16(wplain);

        //Đọc dữ liệu từ file
        std::ifstream infile("100MB.txt");
        if (!infile.is_open()) {
            std::cout << "File not exist" << std::endl;
            exit(1); // thoát chương trình với mã lỗi 1
            }

        std::string line;
        while (std::getline(infile, line)) {
            plain += line + "\n";
        }
        infile.close();

        ////////////////////////////////////////////////////////////////

        // Encryption
        RSAES_OAEP_SHA_Encryptor enc( publicKey );

        StringSource( plain, true,
            new PK_EncryptorFilter( rng, enc,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource

    double elapsedTimeInSeconds;
	unsigned long i = 0, blocks = 1;

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i < blocks; i++)
            enc.Encrypt(rng, reinterpret_cast<const CryptoPP::byte*>(plain.data()), plain.size(), reinterpret_cast<CryptoPP::byte*>(cipher.data()));
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	} while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(plain.size()) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 16384 / 16384;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::wcout << "RSA Encryption: " << std::endl;
	std::wcout << "  " << ghz << " GHz cpu frequency" << std::endl;
	std::wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }
}

void decryptionTime()
{
	#ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

	try
    {
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize( rng, 16384 );

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        string cipher, recovered, plain;

        // Encryption
        RSAES_OAEP_SHA_Encryptor enc( publicKey );
        StringSource( plain, true,
            new PK_EncryptorFilter( rng, enc,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
        ); // StringSource

        // Decryption
        RSAES_OAEP_SHA_Decryptor dec( privateKey );

        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, dec,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        // Check that recovered is the same as plain
        assert( recovered == plain );

    double elapsedTimeInSeconds;
	unsigned long i = 0, blocks = 1;

	CryptoPP::ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i < blocks; i++){
            plain.resize(cipher.size());
            dec.Decrypt(rng, reinterpret_cast<const CryptoPP::byte*>(cipher.data()), cipher.size(), reinterpret_cast<CryptoPP::byte*>(plain.data()));
        }
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	} while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(plain.size()) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 16384 / 16384;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::wcout << "RSA Decryption: " << std::endl;
	std::wcout << "  " << ghz << " GHz cpu frequency" << std::endl;
	std::wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    }
    catch( CryptoPP::Exception& enc )
    {
        cerr << "Caught Exception..." << endl;
        cerr << enc.what() << endl;
    }
}

int main(int argc, char *argv[])
{
	encryptionTime();
	decryptionTime();
}