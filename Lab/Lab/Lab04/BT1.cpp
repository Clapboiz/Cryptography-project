#include <assert.h>
#include <fstream>

#include <hex.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "aes.h"
using CryptoPP::AES;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA1;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#if _MSC_VER <= 1200 // VS 6.0
typedef CryptoPP::ECDSA<ECP, CryptoPP::SHA1> ECDSA_SHA1;
typedef CryptoPP::DL_GroupParameters_EC<ECP> DL_EC;

#endif

#include "oids.h"
using CryptoPP::OID;

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key );
bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey );

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key );
void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key );
void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key );
void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key );

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );
void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key );

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature );
bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature );

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    AutoSeededRandomPool prng;

    // Scratch result
    bool result = false;   
    
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    
    /////////////////////////////////////////////
    // Generate Keys
    result = GeneratePrivateKey( CryptoPP::ASN1::secp160r1(), privateKey );
    assert( true == result );
    if( !result ) { return -1; }

    result = GeneratePublicKey( privateKey, publicKey );
    assert( true == result );
    if( !result ) { return -2; }
    
    /////////////////////////////////////////////
    // Print Domain Parameters and Keys   
    PrintDomainParameters( publicKey );
    PrintPrivateKey( privateKey );
    PrintPublicKey( publicKey );

    /////////////////////////////////////////////
    // Sign and Verify a message      
    string data;
    std::ifstream file("UIT.png", std::ios::binary);
    if (file.is_open()) 
    {
        // Lấy kích thước file
        file.seekg(0, std::ios::end);
        int length = file.tellg();
        file.seekg(0, std::ios::beg);

        // Đọc dữ liệu byte của hình ảnh
        std::byte * data = new std::byte[length];
        file.read(reinterpret_cast<char*>(data), length);

        // Giải phóng bộ nhớ
        delete[] data;
        
        file.close();
    }
    // string message = "Yoda said, Do or do not. There is no try.";
    string signature;

    result = SignMessage( privateKey, data, signature );
    assert( true == result );

    result = VerifyMessage( publicKey, data, signature );
    assert( true == result );
    cout<<signature;

    // Lưu khóa riêng tư
    std::string privateFileName = "private.key";
    SavePrivateKey(privateFileName, privateKey);

    // Lưu khóa công khai
    std::string publicFileName = "public.key";
    SavePublicKey(publicFileName, publicKey);

    return 0;
}

bool GeneratePrivateKey( const OID& oid, ECDSA<ECP, SHA1>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
     
    return key.Validate( prng, 3 );
}

bool GeneratePublicKey( const ECDSA<ECP, SHA1>::PrivateKey& privateKey, ECDSA<ECP, SHA1>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );

    return publicKey.Validate( prng, 3 );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << key.GetPublicElement().x << endl; 
    cout << " Y: " << key.GetPublicElement().y << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, SHA1>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, SHA1>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, SHA1>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, SHA1>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,SHA1>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, SHA1>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;
    using byte = unsigned char;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,SHA1>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}
