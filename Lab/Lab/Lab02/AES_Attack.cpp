#include <iostream>
#include <string>
#include "aes.h"
#include "modes.h"
#include "filters.h"

using CryptoPP::AES;
using CryptoPP::CBC_Mode;

#include "secblock.h"
using CryptoPP::SecByteBlock;

using namespace std;
using namespace CryptoPP;

CryptoPP::byte* find_key(CryptoPP::byte *iv, string ciphertext) {
CryptoPP::byte key[16];

CryptoPP::byte* found_key = new CryptoPP::byte[16];
memset(found_key, 0, 16);

// Kiểm tra đầu vào
if (ciphertext.empty() || iv == NULL)
{
return NULL;
}

// Duyệt từng khả năng của key
for (int i = 0; i < 256; i++) {
for (int j = 0; j < 256; j++) {
key[0] = i;
key[1] = j;

    // Giải mã ciphertext sử dụng key và IV 
    string decryptedtext; 
    try 
    { 
        CBC_Mode<AES>::Decryption decryption(key, sizeof(key), iv); 
        StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedtext))); 
    } 
    catch (CryptoPP::Exception& e) 
    { 
    	continue;   // Bỏ qua các ciphertext không hợp lệ 
    } 

    // Nếu đúng plaintext thì trả về key, ngược lại null 
     if (decryptedtext == "Day la chuong trinh tan cong vao CBC mode cua AES") { 
        memcpy(found_key, key, 16);  
        return found_key; 
    } 
} 
}
return NULL;
}

int main()
{
CryptoPP::byte key[16] = {'k', 'e', 'y', '1', '2', '3', '4', '5', '6', '7', '8', '9', '1', '0', '1', '1'};
CryptoPP::byte iv[16] = {'I', 'V', '1', '2', '3', '4', '5', '6', '7', '8', '9', '1', '0', '1', '1', '2'};

// Kiểm tra đầu vào
if (key == NULL || iv == NULL || sizeof(key) != 16 || sizeof(iv) != 16)
{
exit(1);
}

// Plaintext cố định
string plaintext = "Day la chuong trinh tan cong vao CBC mode cua AES";
cout << "plaintext: " << plaintext << endl;

// Mã hóa plaintext
string ciphertext;
try
{
CBC_Mode<AES>::Encryption encryption(key, 16, iv);
StringSource(plaintext, true, new StreamTransformationFilter(encryption, new StringSink(ciphertext)));
}
catch (CryptoPP::Exception& e)
{
cerr << e.what() << endl;
exit(1);
}
cout << "Ciphertext: " << ciphertext << endl;

// Tìm key sử dụng IV và ciphertext
CryptoPP::byte found_key[16];
CryptoPP::byte* found = find_key(iv, ciphertext);
if (found != NULL)
{
memcpy(found_key, found, 16);
cout << "Found key: " << int(found_key[0]) << endl;
}
else
{
cout << "Không tìm thấy khóa." << endl;
exit(1);
}

// Giải mã ciphertext sử dụng key và IV
string decryptedtext;
try
{
CBC_Mode<AES>::Decryption decryption(found_key, 16, iv);
StringSource(ciphertext, true, new StreamTransformationFilter(decryption, new StringSink(decryptedtext)));
}
catch (CryptoPP::Exception& e)
{
cerr << e.what() << endl;
exit(1);
}
if (decryptedtext.empty())
{
cout << "Giải mã thất bại." << endl;
exit(1);
}
cout << "Recovered text: " << decryptedtext << endl;
}