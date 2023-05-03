#include <iostream>
using std::cout;
using std::endl;

#include <iomanip>
using std::hex;

#include <string>
using std::string;

#include "rsa.h"
using CryptoPP::RSA;

#include "integer.h"
using CryptoPP::Integer;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::InvertibleRSAFunction;

int main(int argc, char** argv)
{
    AutoSeededRandomPool prng;

    // Initialize RSA parameters
    Integer n("0xbeaadb3d839f3b5f"), e("0x11"), d("0x21a5ae37b9959db9");
    InvertibleRSAFunction parameters;
    parameters.Initialize(n, e, d);

    // Create private and public keys
    RSA::PrivateKey privKey(parameters);
    RSA::PublicKey pubKey(parameters);

    // Print key parameters
    cout << "modulus: " << hex << privKey.GetModulus() << endl;
    cout << "private exp: " << hex << privKey.GetPrivateExponent() << endl;
    cout << "public exp: " << hex << pubKey.GetPublicExponent() << endl;
    cout << endl;

    // Encrypt and decrypt a message
    string message = "secret";
    cout << "message: " << message << endl;

	// Treat the message as a big endian array
	Integer m((byte *)message.data(), message.size());
    cout << "m: " << hex << m << endl;

    // Encrypt
    Integer c = pubKey.ApplyFunction(m);
    cout << "c: " << hex << c << endl;

    // Decrypt
    Integer r = privKey.CalculateInverse(prng, c);
    cout << "r: " << hex << r << endl;

	// Round trip the message
	size_t req = r.MinEncodedSize();
	string recovered;
	recovered.resize(req);
	r.Encode(reinterpret_cast<byte *>(recovered.data()), recovered.size());

	cout << "recovered: " << recovered << endl;

    return 0;
}