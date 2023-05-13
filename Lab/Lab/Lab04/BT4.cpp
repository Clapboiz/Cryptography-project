#include <iostream>
#include <string>
#include "cryptlib.h"
#include "filters.h"
#include "md5.h"
#include "sha3.h"
#include "sha.h"
#include "shake.h"
#include "hex.h"

using namespace std;
using namespace CryptoPP;

void md5(string input, string& digest) {
    MD5 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha224(string input, string& digest) {
    SHA224 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha256(string input, string& digest) {
    SHA256 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha384(string input, string& digest) {
    SHA384 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha512(string input, string& digest) {
    SHA512 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha3_224(string input, string& digest) {
    SHA3_224 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha3_256(string input, string& digest) {
    SHA3_256 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha3_384(string input, string& digest) {
    SHA3_384 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void sha3_512(string input, string& digest) {
    SHA3_512 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void shake128(string input, string& digest) {
    SHAKE128 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}

void shake256(string input, string& digest) {
    SHAKE256 hash;

    StringSource(input, true, new HashFilter(hash, new HexEncoder(new StringSink(digest))));
}


int main(int argc, char* argv[])
{
    string input;
    string digest;
    int hashIndex;
    string hashName;

    cout << "Ham bam : " << endl;
    cout << "1.MD5" << endl;
    cout << "2.SHA224" << endl;
    cout << "3.SHA256" << endl;
    cout << "4.SHA384" << endl;
    cout << "5.SHA512" << endl;
    cout << "6.SHA3_224" << endl;
    cout << "7.SHA3_256" << endl;
    cout << "8.SHA3_384" << endl;
    cout << "9.SHA3_512" << endl;
    cout << "10.SHAKE128" << endl;
    cout << "11.SHAKE256" << endl << endl;

    cout << "Nhap input : ";
    cin >> input;


    do {
        cout << "Nhap ham bam (so nguyen) : ";
        cin >> hashIndex;

        switch (hashIndex) {
        case 1:
            md5(input, digest);
            hashName = "MD5";
            break;
        case 2:
            sha224(input, digest);
            hashName = "SHA224";
            break;
        case 3:
            sha256(input, digest);
            hashName = "SHA256";
            break;
        case 4:
            sha384(input, digest);
            hashName = "SHA384";
            break;
        case 5:
            sha512(input, digest);
            hashName = "SHA512";
            break;
        case 6:
            sha3_224(input, digest);
            hashName = "SHA3_224";
            break;
        case 7:
            sha3_256(input, digest);
            hashName = "SHA3_256";
            break;
        case 8:
            sha3_384(input, digest);
            hashName = "SHA3_384";
            break;
        case 9:
            sha3_512(input, digest);
            hashName = "SHA3_512";
            break;
        case 10:
            shake128(input, digest);
            hashName = "SHAKE128";
            break;
        case 11:
            shake256(input, digest);
            hashName = "SHAKE256";
            break;
        default:
            cout << "Vui long nhap lai !" << endl;
            break;
        }
    } while (hashIndex > 11 || hashIndex < 1);


    cout << "Input : " << input << std::endl;
    cout << hashName + " hash : " << digest << std::endl;

    return 0;
}