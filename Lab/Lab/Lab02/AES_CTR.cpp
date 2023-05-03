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
#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

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

int main(int argc, char* argv[]) {
  #ifdef  __linux__ // For linux
    setlocale(LC_ALL, "");
  #elif _WIN32 	  // For windows
    _setmode(_fileno(stdin), _O_U16TEXT);
    _setmode(_fileno(stdout), _O_U16TEXT);
  #endif

  AutoSeededRandomPool prng;

  string skey, siv;
  wstring wkey, wiv;


  wcout<<L"Enter plain(CTR Mode): ";
  wstring wplain;
  getline(wcin, wplain);

  string plain = wstring_to_utf16(wplain);

  SecByteBlock key(16);
  wcout << L"Enter key (16 bytes): ";
  fflush(stdin);
  getline(wcin, wkey);
  skey = wstring_to_utf16(wkey);
  for (int i=0; i<8 ;i++) {
    key[i]= (char) skey[i];
  }

  CryptoPP::byte iv[16];
  wcout << L"Enter iv (16 bytes): ";
  fflush(stdin);
  getline(wcin, wiv);
  siv = wstring_to_utf16(wiv);
  for (int i=0; i<8 ;i++) {
    iv[i]= (char) siv[i];
  }

  string cipher, encoded, recovered;

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
    wcout << "plain text: " << wplain << endl;
    CTR_Mode< AES >::Encryption e;
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
    CTR_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, key.size(), iv);

    StringSource s(cipher, true,
                   new StreamTransformationFilter(d,
                                                  new StringSink(recovered)) // StreamTransformationFilter
    );
    system("pause");
  return 0;
}
