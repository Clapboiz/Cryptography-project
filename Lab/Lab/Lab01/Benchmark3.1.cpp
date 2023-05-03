#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "des.h"
using CryptoPP::DES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

// Library support UTF-16
#include <io.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;
#include <chrono>
#include <thread>

#include <iomanip>
#include <fstream>
#include "hrtimer.h"
using CryptoPP::ThreadUserTimer;

using namespace std;
using namespace CryptoPP;

// convert UTF-8 string to wstring
wstring utf8_to_wstring(const string &str) {
  using convert_type = std::codecvt_utf8<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.from_bytes(str);
}

// convert wstring to UTF-8 string
string wstring_to_utf8(const wstring &wstr) {
  using convert_type = std::codecvt_utf8<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.to_bytes(wstr);
}

int main(int argc, char* argv[]) {
  #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

  AutoSeededRandomPool prng;

  SecByteBlock key(DES::DEFAULT_KEYLENGTH);
  prng.GenerateBlock(key, key.size());

  CryptoPP::byte iv[DES::BLOCKSIZE];
  prng.GenerateBlock(iv, sizeof(iv));

  //plain1.txt data < 64 bit

  //plain2.txt data utf-16
  wcout<<L"Enter plain: ";
  wstring wplain;
  getline(wcin, wplain);
    string plain = wstring_to_utf8(wplain);

  //plain3.txt data > 1MB
  // string plain = InputFromFile(L"plain3.txt");
  string cipher, encoded, recovered;

  // key
  // convert key
  encoded.clear();
  StringSource(key, key.size(), true,
      new HexEncoder( 
        new StringSink(encoded)) // HexEncoder
  ); // StringSource
  wstring encodedKey(encoded.begin(), encoded.end());
  wcout << "key: " << encodedKey << endl;

  // convert iv
  encoded.clear();
  StringSource(iv, sizeof(iv), true,
      new HexEncoder(
        new StringSink(encoded)) // HexEncoder
  ); // StringSource

  wstring encodedIV(encoded.begin(), encoded.end());
  wcout << "iv: " << encodedIV << endl;

  //* Encryption
    CBC_Mode< DES >::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);

    StringSource(plain, true,
        new StreamTransformationFilter(e,
          new StringSink(cipher)) // StreamTransformationFilter
    ); // StringSource

  // convert cipher
  encoded.clear();
  StringSource(cipher, true,
      new HexEncoder(
        new StringSink(encoded)) // HexEncoder
  ); // StringSource

  wstring encodedCipher(encoded.begin(), encoded.end());
  wcout << "cipher text: " << encodedCipher << endl;

  //* Decryption
    CBC_Mode<DES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(recovered)) // StreamTransformationFilter
    );

  // Benchmark
  const int BUF_SIZE = RoundUpToMultipleOf(2048U,dynamic_cast<StreamTransformation&>(d).OptimalBlockSize());
  const double runTimeInSeconds = 3.0;
  AlignedSecByteBlock buf(BUF_SIZE);
  prng.GenerateBlock(buf, buf.size());

  double elapsedTimeInSeconds;
  unsigned long i=0, blocks=1;

  ThreadUserTimer timer;
  timer.StartTimer();

  do {
    blocks *= 2;
    for (; i<blocks; i++) 
      d.ProcessString(buf, BUF_SIZE);
    elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
  }
  while (elapsedTimeInSeconds < runTimeInSeconds);

  const double cpuFreq = 3.3 * 1000 * 1000 * 1000;
  const double bytes = static_cast<double>(BUF_SIZE) * blocks;
  const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
  const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

  wcout << "  " << cpb << " cycles per byte " << std::endl;
  wcout << "  " << mbs << " MiB per second " << std::endl;

    system ("pause");
  return 0;
}
