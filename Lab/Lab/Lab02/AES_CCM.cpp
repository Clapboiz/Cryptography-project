#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::byte;
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CCM;

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
wstring utf16_to_wstring(const string &str)
{
  using convert_type = std::codecvt_utf16<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.from_bytes(str);
}

// convert wstring to UTF-16 string
string wstring_to_utf16(const wstring &wstr)
{
  using convert_type = std::codecvt_utf16<wchar_t>;
  wstring_convert<convert_type, wchar_t> converter;
  return converter.to_bytes(wstr);
}

int main(int argc, char *argv[])
{
#ifdef __linux__ // For linux
  setlocale(LC_ALL, "");
#elif _WIN32 // For windows
  _setmode(_fileno(stdin), _O_U16TEXT);
  _setmode(_fileno(stdout), _O_U16TEXT);
#endif

  AutoSeededRandomPool prng;

  string skey, siv;
  wstring wkey, wiv;

  wcout << L"Enter plain(CCM Mode): ";
  wstring wplain;
  getline(wcin, wplain);

  string plain = wstring_to_utf16(wplain);
  SecByteBlock key(16);
  wcout << L"Enter key (16 bytes): ";
  fflush(stdin);
  getline(wcin, wkey);
  skey = wstring_to_utf16(wkey);
  for (int i = 0; i < 16; i++)
  {
    key[i] = (char)skey[i];
  }

  CryptoPP::byte iv[12];
  wcout << L"Enter iv (12 bytes): ";
  fflush(stdin);
  getline(wcin, wiv);
  siv = wstring_to_utf16(wiv);
  for (int i = 0; i < 12; i++)
  {
    iv[i] = (char)siv[i];
  }
  const int TAG_SIZE = 8;
  string cipher, encoded, recovered;

  // convert key
  encoded.clear();
  StringSource(key, key.size(), true,
               new HexEncoder(
                   new StringSink(encoded)) // HexEncoder
  );                                        // StringSource

  wstring encodedKey(encoded.begin(), encoded.end());
  wcout << "key: " << encodedKey << endl;

  // convert iv
  encoded.clear();
  StringSource(iv, sizeof(iv), true,
               new HexEncoder(
                   new StringSink(encoded)) // HexEncoder
  );                                        // StringSource

  wstring encodedIV(encoded.begin(), encoded.end());
  wcout << "iv: " << encodedIV << endl;

  //* Encryption
  CCM<AES, TAG_SIZE>::Encryption e;
  e.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));
  e.SpecifyDataLengths(0, recovered.size(), 0);

  StringSource(recovered, true,
               new AuthenticatedEncryptionFilter(e,
                                                 new StringSink(cipher)) // AuthenticatedEncryptionFilter
  );                                                                     // StringSource

  // convert cipher
  encoded.clear();
  StringSource(cipher, true,
               new HexEncoder(
                   new StringSink(encoded)) // HexEncoder
  );                                        // StringSource

  wstring encodedCipher(encoded.begin(), encoded.end());
  wcout << "cipher text: " << encodedCipher << endl;

  //* Decryption
  CCM<AES, TAG_SIZE>::Decryption d;
  d.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
  d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);

  AuthenticatedDecryptionFilter df(d,
                                   new StringSink(recovered)); // AuthenticatedDecryptionFilter
  StringSource ss2(cipher, true,
                   new Redirector(df)); // StringSource
  system("pause");
  return 0;
}
