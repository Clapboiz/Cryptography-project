#include "rsa.h"
#include "pssr.h"
#include "sha.h"
#include "files.h"
#include "osrng.h"
#include "SecBlock.h"

#include <string>
#include <iostream>
#include <fstream>

using namespace CryptoPP;

int main()
{
    AutoSeededRandomPool rng;

    // Read the message from file
    std::ifstream messageFile("input.txt");
    if (!messageFile.is_open()) {
        std::cout << "Error opening message file" << std::endl;
        return 1;
    }
    std::string message;
    std::getline(messageFile, message);
    messageFile.close();

    // Load private key
    ByteQueue privateKeyBytes;
    FileSource privateKeyFile("private_key.bin", true);
    privateKeyFile.TransferTo(privateKeyBytes);
    privateKeyBytes.MessageEnd();

    RSA::PrivateKey privateKey;
    privateKey.Load(privateKeyBytes);

    // Sign message
    RSASS<PSS, SHA1>::Signer signer(privateKey);
    SecByteBlock signature(signer.MaxSignatureLength());
    size_t signatureLen = signer.SignMessage(rng, (const byte*)message.data(), message.size(), signature);

    // Save the signed message to file
    std::ofstream signedMessageFile("signed_message.txt", std::ios_base::binary);
    signedMessageFile.write(reinterpret_cast<const char*>(signature.data()), signatureLen);
    signedMessageFile.write(message.data(), message.size());
    signedMessageFile.close();

    // Load public key
    ByteQueue publicKeyBytes;
    FileSource publicKeyFile("public_key.bin", true);
    publicKeyFile.TransferTo(publicKeyBytes);
    publicKeyBytes.MessageEnd();

    RSA::PublicKey publicKey;
    publicKey.Load(publicKeyBytes);

    // Verify the signature
    std::ifstream signedMessageFileStream("signed_message.txt", std::ios_base::binary);
    if (!signedMessageFileStream.is_open()) {
        std::cout << "Error opening signed message file" << std::endl;
        return 1;
    }
    signedMessageFileStream.seekg(0, std::ios::end);
    size_t signedMessageLen = signedMessageFileStream.tellg();
    signedMessageFileStream.seekg(0, std::ios::beg);

    SecByteBlock signedMessage(signedMessageLen);
    signedMessageFileStream.read(reinterpret_cast<char*>(signedMessage.data()), signedMessageLen);
    signedMessageFileStream.close();

    SecByteBlock receivedSignature((const unsigned char*)signedMessage.data(), signatureLen);
    std::string receivedMessage(reinterpret_cast<const char*>(signedMessage.data() + signatureLen), signedMessageLen - signatureLen);

    bool result = false;
    RSASS<PSS, SHA1>::Verifier verifier(publicKey);
    result = verifier.VerifyMessage((const byte*)receivedMessage.data(), receivedMessage.size(), receivedSignature, receivedSignature.size());

    if (result) {
        std::cout << "Signature is valid." << std::endl;
    }
    else {
        std::cout << "Signature is invalid." << std::endl;
    }

    system ("pause");
    return 0;
}
