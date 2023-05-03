#include <iostream>
using std::cout;
using std::endl;

#include <iomanip>
using std::hex;

#include <string>
using std::string;

#include "cryptlib.h"
#include "rsa.h"
#include "integer.h"
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::byte;

int main(int argc, char** argv)
{
    AutoSeededRandomPool prng;
    InvertibleRSAFunction parameters;

    // Below, the values for d and e were swapped
    Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");

    RSA::PrivateKey privKey( parameters );
    privKey.Initialize(n, d, e);

    RSA::PublicKey pubKey( parameters );
    pubKey.Initialize(n, d);

    string message, recovered;
    Integer m, c, r;

    message = "secret";
    cout << "message: " << message << endl;

    // Treat the message as a big endian array
    m = Integer((const byte *)message.data(), message.size());
    cout << "m: " << hex << m << endl;

    // Encrypt
    c = pubKey.ApplyFunction(m);
    cout << "c: " << hex << c << endl;

    // Decrypt
    r = privKey.CalculateInverse(prng, c);
    cout << "r: " << hex << r << endl;

    // Round trip the message
    size_t req = r.MinEncodedSize();
    recovered.resize(req);
    r.Encode((CryptoPP::byte *)recovered.data(), recovered.size());

    cout << "recovered: " << recovered << endl; 

    return 0;
}