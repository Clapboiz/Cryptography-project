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

#include "xts.h"
using CryptoPP::XTS_Mode;

#include "assert.h"
using namespace std;
using namespace CryptoPP;

#include <ctime>
#include "hrtimer.h"

// Library support UTF-16
#include <io.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

using namespace std;

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

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

const double runTimeInSeconds = 3.0;
const double cpuFreq = 3.3 * 1000 * 1000 * 1000;

void AESencryptionTime()
{
   #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

	using namespace CryptoPP;
	AutoSeededRandomPool prng;

  string skey, siv;
  wstring wkey, wiv;
  
  wcout<<L"Enter plain(XTS Mode): ";
  wstring wplain;
  getline(wcin, wplain);

  string plain = wstring_to_utf16(wplain);

	SecByteBlock key(32);
	prng.GenerateBlock(key, key.size());

	XTS_Mode<AES>::Encryption cipher;
	cipher.SetKeyWithIV(key, key.size(), key);

    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv,iv.size());

	const int BUF_SIZE = RoundUpToMultipleOf(2048U,
											 dynamic_cast<StreamTransformation &>(cipher).OptimalBlockSize());

	AlignedSecByteBlock buf(BUF_SIZE);
	prng.GenerateBlock(buf, buf.size());

	double elapsedTimeInSeconds;
	unsigned long i = 0, blocks = 1;

	ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i < blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	} while (elapsedTimeInSeconds < runTimeInSeconds);

	const double bytes = static_cast<double>(BUF_SIZE) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::wcout << "AES XTS Mode Encryption: " << std::endl;
	std::wcout << "  " << ghz << " GHz cpu frequency" << std::endl;
	std::wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

void AESdecryptionTime()
{
	#ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

	using namespace CryptoPP;
	AutoSeededRandomPool prng;

	SecByteBlock key(32);
	prng.GenerateBlock(key, key.size());

	XTS_Mode<AES>::Decryption cipher;
	cipher.SetKeyWithIV(key, key.size(), key);

	const int BUF_SIZE = RoundUpToMultipleOf(2048U,
											 dynamic_cast<StreamTransformation &>(cipher).OptimalBlockSize());

	AlignedSecByteBlock buf(BUF_SIZE);
	prng.GenerateBlock(buf, buf.size());

	double elapsedTimeInSeconds;
	unsigned long i = 0, blocks = 1;

	ThreadUserTimer timer;
	timer.StartTimer();

	do
	{
		blocks *= 2;
		for (; i < blocks; i++)
			cipher.ProcessString(buf, BUF_SIZE);
		elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
	} while (elapsedTimeInSeconds < runTimeInSeconds);

	const double bytes = static_cast<double>(BUF_SIZE) * blocks;
	const double ghz = cpuFreq / 1000 / 1000 / 1000;
	const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
	const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

	std::wcout << "AES XTS Mode Decryption: " << std::endl;
	std::wcout << "  " << ghz << " GHz cpu frequency" << std::endl;
	std::wcout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
	std::wcout << "  " << mbs << " MiB per second (MiB)" << std::endl;
}

int main(int argc, char *argv[])
{
	AESencryptionTime();
	AESdecryptionTime();
}

