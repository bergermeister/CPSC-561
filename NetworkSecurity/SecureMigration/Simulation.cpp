/**
 * @file
 * @brief
 *
 *
 * @details
 * @par
 *
 */
// Application Includes
#include <Simulation.h>
#include <Utility.h>
#include <DiffieHellman.h>
#include <AES.h>
#include <RSACryptosystem.h>

// OpenSSL Includes
#include <openssl/bn.h>

// StdLib Includes
#include <iostream>
#include <chrono>
#include <iomanip>

using HighResClock = std::chrono::high_resolution_clock;
using Milliseconds = std::chrono::duration< double, std::ratio< 1, 1000 > >;

using namespace SecureMigration;

/**
 * Secure Data Migration Simulation using Diffie-Hellman Key Exchange.
 *
 * @msc
 *  Alice, Bob, Carol;
 *
 *  ---          [label="Initialization", ID="*"];
 *  Alice=>Alice [label="Generate (p,g)", URL="@ref DiffieHellman::Session::GenerateParams"];
 *  Alice=>Alice [label="Initialize a",   URL="@ref DiffieHellman::Session::Initialize"];
 *  Alice->Bob   [label="(p,g)",          URL=""];
 *  Alice->Carol [label="(p,g)",          URL=""];
 *  Bob=>Bob     [label="Initialize b",   URL="@ref DiffieHellman::Session::Initialize"];
 *  Carol=>Carol [label="Initialize c",   URL="@ref DiffieHellman::Session::Initialize"];
 *
 *  ---          [label="Exchange First Stage Public Keys", ID="*"];
 *  Alice->Bob   [label="g^a mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Alice->Carol [label="g^a mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob->Alice   [label="g^b mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob->Carol   [label="g^b mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol->Alice [label="g^c mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol->Bob   [label="g^c mod p", URL="@ref DiffieHellman::Session::Derive"];
 *
 *  ---          [label="Exchange Second Stage Public Keys", ID="*"];
 *  Alice->Bob   [label="g^ca mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Alice->Carol [label="g^ba mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob->Alice   [label="g^cb mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob->Carol   [label="g^ab mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol->Alice [label="g^bc mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol->Bob   [label="g^ac mod p", URL="@ref DiffieHellman::Session::Derive"];
 *
 *  ---          [label="Derive Shared Secret", ID="*"];
 *  Alice=>Alice [label="Derive g^bca mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Alice=>Alice [label="Derive g^cba mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob=>Bob     [label="Derive g^acb mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Bob=>Bob     [label="Derive g^cab mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol=>Carol [label="Derive g^abc mod p", URL="@ref DiffieHellman::Session::Derive"];
 *  Carol=>Carol [label="Derive g^bac mod p", URL="@ref DiffieHellman::Session::Derive"];
 *
 *  ---          [label="Verify Shared Secret is valid", ID="*"];
 *  Alice=>Alice [label="Verify g^bca == g^cba"];
 *  Bob=>Bob     [label="Verify g^acb == g^cab"];
 *  Carol=>Carol [label="Verify g^abc == g^bac"];
 * @endmsc
 */
int Simulation::RunDiffieHellman( const unsigned char* plaintext, const int size, const int keyLen )
{
   const int BytesPerLineDef = 32;
   int status = 0;
   unsigned char* ciphertext = new unsigned char[ size + 32 ];
   unsigned char* decrypted = new unsigned char[ size + 32 ];

   DiffieHellman::Session Alice;
   DiffieHellman::Session Bob;
   DiffieHellman::Session Carol;
   Key* keyGab;
   Key* keyGac;
   Key* keyGba;
   Key* keyGbc;
   Key* keyGca;
   Key* keyGcb;
   Key* keyGabc;
   Key* keyGacb;
   Key* keyGbca;
   Key* keyGbac;
   Key* keyGcab;
   Key* keyGcba;
   Key* dhParams;

   std::chrono::time_point< HighResClock > start;
   double elapsedGen;
   double elapsedExc;
   double elapsedCmp;

   std::cout << "Secure Migration (Diffie-Hellman, AES-256-CBC) BEGIN" << std::endl;

   /// @par Process Design Language
   /// -# Alice generates Diffie-Hellman Parameters (p,g)
   start = std::chrono::high_resolution_clock::now( );
   DiffieHellman::Session::GenerateParams( keyLen, &dhParams );
   #ifdef _DEBUG
   std::cout << "> Alice Generated (p,g)" << std::endl;
   #endif
   elapsedGen = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );
   start = std::chrono::high_resolution_clock::now( );

   /// -# Alice Initializes Private Key a
   Alice.Initialize( *dhParams );
   #ifdef _DEBUG
   std::cout << "> Alice Initialized a" << std::endl;
   #endif

   /// -# Alice sends parameters (p,g) to Bob
   Bob.Initialize( *dhParams );
   #ifdef _DEBUG
   std::cout << "> Alice->Bob [p,g]" << std::endl;
   #endif

   /// -# Alice sends parameters (p,g) to Carol
   Carol.Initialize( *dhParams );
   #ifdef _DEBUG
   std::cout << "> Alice->Carol [p,g]" << std::endl;
   #endif

   /// -# Alice sends g^a mod p to Bob
   Bob.Derive( *Alice.PublicKey( ) );
   keyGab = new Key( *Bob.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Alice->Bob [g^a mod p]" << std::endl;
   #endif

   /// -# Alice sends g^a mod p to Carol
   Carol.Derive( *Alice.PublicKey( ) );
   keyGac = new Key( *Carol.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Alice->Carol [g^a mod p]" << std::endl;
   #endif

   /// -# Bob sends g^b mod p to Alice
   Alice.Derive( *Bob.PublicKey( ) );
   keyGba = new Key( *Alice.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Bob->Alice [g^b mod p]" << std::endl;
   #endif

   /// -# Bob sends g^b mod p to Carol
   Carol.Derive( *Bob.PublicKey( ) );
   keyGbc = new Key( *Carol.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Bob->Carol [g^b mod p]" << std::endl;
   #endif

   /// -# Carol sends g^c mod p to Alice
   Alice.Derive( *Carol.PublicKey( ) );
   keyGca = new Key( *Alice.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Carol->Alice [g^c mod p]" << std::endl;
   #endif

   /// -# Carol sends g^c mod p to Bob
   Bob.Derive( *Carol.PublicKey( ) );
   keyGcb = new Key( *Bob.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Carol->Bob [g^c mod p]" << std::endl;
   #endif

   /// -# Alice sends Bob   [g^ca mod p]
   /// -# Alice sends Carol [g^ba mod p]
   /// -# Bob   sends Alice [g^cb mod p]
   /// -# Bob   sends Carol [g^ab mod p]
   /// -# Carol sends Alice [g^bc mod p]
   /// -# Carol sends Bob   [g^ac mod p]

   /// -# Alice Derives Shared Secrets g^bca and g^cba
   /// -# Alice verifies g^bca == g^cba
   Alice.Derive( *keyGbc ); 
   keyGbca = new Key( *Alice.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Alice derived [g^bca mod p]" << std::endl;
   #endif
   
   Alice.Derive( *keyGcb );
   keyGcba = new Key( *Alice.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Alice derived [g^cba mod p]" << std::endl;
   std::cout << "> Alice verifies [g^bca == g^cba]" << ( ( *keyGbca == *keyGcba ) ? "" : " ERROR" ) << std::endl;
   #endif

   /// -# Bob Derives Shared Secrets g^acb and g^cab
   /// -# Bob verifies g^acb == g^cab
   Bob.Derive( *keyGac );
   keyGacb = new Key( *Bob.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Bob derived [g^acb mod p]" << std::endl;
   #endif
   
   Bob.Derive( *keyGca );
   keyGcab = new Key( *Bob.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Bob derived [g^cab mod p]" << std::endl;
   std::cout << "> Bob verifies [g^acb == g^cab]" << ( ( *keyGbca == *keyGcba ) ? "" : " ERROR" ) << std::endl;
   #endif

   /// -# Carol Derives Shared Secrets g^abc and g^bac
   /// -# Bob verifies g^abc == g^bac
   Carol.Derive( *keyGab );
   keyGabc = new Key( *Carol.Secret( ) );
   #ifdef _DEBUG
   std::cout << "> Carol derived [g^abc mod p]" << std::endl;
   #endif

   Carol.Derive( *keyGba );
   keyGbac = new Key( *Carol.Secret( ) );
   #ifdef _DEBUG  
   std::cout << "> Carol derived [g^bac mod p]" << std::endl;
   std::cout << "> Carol verifies [g^abc == g^bac]" << ( ( *keyGbca == *keyGcba ) ? "" : " ERROR" ) << std::endl;
   #endif

   elapsedExc = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );
   start = std::chrono::high_resolution_clock::now( );

   /// -# Encrypt data at Bob and send to Carol
   status = AES::Encrypt( plaintext, size, Bob.Secret( )->Buffer( ), &Bob.Secret( )->Buffer( )[ 32 ], ciphertext );
   #ifdef _DEBUG
   std::cout << "> Bob encrypted plaintext and sent ciphertext to Carol" << std::endl;
   #endif

   /// -# Decrypt data at Carol received from Bob
   status = AES::Decrypt( ciphertext, status, Carol.Secret( )->Buffer( ), &Carol.Secret( )->Buffer( )[ 32 ], decrypted );
   #ifdef _DEBUG
   std::cout << "> Carol received ciphertext from Bob and decrypted plaintext" << std::endl;
   #endif

   elapsedCmp = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );

   /// -# Verify the decrypted data matches the plaintext
   status = std::memcmp( reinterpret_cast< const void* >( plaintext ), reinterpret_cast< const void* >( decrypted ), status );
   if( status == 0 )
   {
      std::cout << "> SUCCESS: Decrypted text matches plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "> FAILURE: Decrypted text does not match plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }  

   std::cout << "> Plaintext Size:        " << size << " Bytes" << std::endl;
   std::cout << "> Key Length:            " << keyLen << " Bits" << std::endl;
   std::cout << "> Parameter Generation:  " << std::setprecision( 6 ) << elapsedGen << " Milliseconds" << std::endl;
   std::cout << "> Key Exchange:          " << std::setprecision( 6 ) << elapsedExc << " Milliseconds" << std::endl;
   std::cout << "> Encryption/Decryption: " << std::setprecision( 6 ) << elapsedCmp << " Milliseconds" << std::endl;
   std::cout << "> Total:                 " << std::setprecision( 6 ) 
             << ( elapsedGen + elapsedExc + elapsedCmp ) << " Milliseconds" << std::endl;

   delete keyGab;
   delete keyGac;
   delete keyGba;
   delete keyGbc;
   delete keyGca;
   delete keyGcb;
   delete keyGabc;
   delete keyGacb;
   delete keyGbca;
   delete keyGbac;
   delete keyGcab;
   delete keyGcba;
   delete[ ] ciphertext;
   delete[ ] decrypted;

   std::cout << "Secure Migration (Diffie-Hellman,AES-256-CBC) END" << std::endl << std::endl;

   return( status );
}

/**
 * @msc
 *  Alice, Bob, Carol;
 *
 *  ---          [label="Initialization", ID="*"];
 *  Alice=>Alice [label="Generate Secret Key",              URL="@ref BN_generate_prime"];
 *  Alice=>Alice [label="Generate Public/Private Key Pair", URL="@ref RSACryptosystem::Cipher::Initialize"];
 *  Bob=>Bob     [label="Generate Public/Private Key Pair", URL="@ref RSACryptosystem::Cipher::Initialize"];
 *  Carol=>Carol [label="Generate Public/Private Key Pair", URL="@ref RSACryptosystem::Cipher::Initialize"];
 *
 *  ---          [label="Distributed Secret Key", ID="*"];
 *  Alice->Bob   [label="Requests B"];
 *  Alice<<Bob   [label="B"];
 *  Alice<=Alice [label="Encrypt Secret Key", URL="@ref RSACryptosystem::Cipher::Encrypt"];
 *  Alice->Bob   [label="Encrypted Secret Key"];
 *  Bob=>Bob     [label="Decrypt Secret Key", URL="@ref RSACryptosystem::Cipher::Decrypt"];
 *  Alice->Carol [label="Requests C"];
 *  Alice<<Carol [label="C"];
 *  Alice<=Alice [label="Encrypt Secret Key", URL="@ref RSACryptosystem::Cipher::Encrypt"];
 *  Alice->Carol [label="Encrypted Secret Key"];
 *  Carol=>Carol [label="Decrypt Secret Key", URL="@ref RSACryptosystem::Cipher::Decrypt"];
 * @endmsc
 */
int Simulation::RunRSA( const unsigned char* plaintext, const int size, const int keyLen )
{
   int                     status = 0;
   BIGNUM*                 prime;
   Key*                    rsaKey;
   int                     bytes = ( ( keyLen + 7 ) / 8 ) - 11;
   int                     length;
   unsigned char*          buffer;
   unsigned char*          keyBobP    = new unsigned char[ ( keyLen + 7 ) / 8 ];
   unsigned char*          keyBobC    = new unsigned char[ ( keyLen + 7 ) / 8 ];
   unsigned char*          keyCarolP  = new unsigned char[ ( keyLen + 7 ) / 8 ];
   unsigned char*          keyCarolC  = new unsigned char[ ( keyLen + 7 ) / 8 ];
   unsigned char*          ciphertext = new unsigned char[ size + 32 ];
   unsigned char*          decrypted  = new unsigned char[ size + 32 ];
   RSACryptosystem::Cipher Alice;
   RSACryptosystem::Cipher Bob;
   RSACryptosystem::Cipher Carol;

   std::chrono::time_point< HighResClock > start;
   double elapsedGen;
   double elapsedExc;
   double elapsedCmp;
    
   std::cout << "Secure Migration (RSA Cryptosystem, AES-256-EBC) BEGIN" << std::endl;

   /// @par Process Design Language
   /// -# Alice generates a secret key
   start = std::chrono::high_resolution_clock::now( );
   prime = BN_generate_prime( NULL, keyLen, 1, NULL, NULL, NULL, NULL );
   buffer = new unsigned char[ ( keyLen + 7 ) / 8 ];
   BN_bn2bin( prime, buffer );
   rsaKey = new Key( buffer, ( keyLen + 7 ) / 8 );
   BN_free( prime );
   delete[ ] buffer;
   #ifdef _DEBUG
   std::cout << "> Alice generated Secret Key" << std::endl;
   #endif
   elapsedGen = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );
   start = std::chrono::high_resolution_clock::now( );

   /// -# Alice, Bob, and Carol generate Public/Private Key Pair
   Alice.Initialize( keyLen );
   #ifdef _DEBUG
   std::cout << "> Alice generate Public/Private Key Pair" << std::endl;
   #endif
   Bob.Initialize( keyLen );
   #ifdef _DEBUG
   std::cout << "> Bob generate Public/Private Key Pair" << std::endl;
   #endif
   Carol.Initialize( keyLen );
   #ifdef _DEBUG
   std::cout << "> Carol generate Public/Private Key Pair" << std::endl; 
   #endif   
   
   /// -# Alice requests Bob's Public Key B
   /// -# Bob sends his Public Key B to Alice
   /// -# Alice encrypts the Secret Key using B
   length = Alice.Encrypt( rsaKey->Buffer( ), keyBobC, bytes, *Bob.PublicKey( ) );
   #ifdef _DEBUG
   std::cout << "> Alice encrypted " << ( bytes * 8 ) << " bits of " << keyLen << " bit Secret Key using Bob's Public Key" << std::endl;
   #endif   

   /// -# Alice Sends Encrypted Secret Key to Bob
   /// -# Bob Decrypts Secret Key
   ( void )Bob.Decrypt( keyBobC, keyBobP, length );
   #ifdef _DEBUG  
   std::cout << "> Alice sent the Encrypted Secret Key to Bob" << std::endl;
   std::cout << "> Bob Decypts the Secret Key" << std::endl;
   #endif
   
   /// -# Alice requests Carol's Public Key C
   /// -# Carol sends her Public Key C to Alice
   /// -# Alice encrypts the Secret Key using C
   length = Alice.Encrypt( rsaKey->Buffer( ), keyCarolC, bytes, *Carol.PublicKey( ) );
   #ifdef _DEBUG
   std::cout << "> Alice encrypted " << ( bytes * 8 ) << " bits of " << keyLen << " bit Secret Key using Carol's Public Key" << std::endl;
   #endif
   
   /// -# Alice Sends Encrypted Secret Key to Carol
   /// -# Carol Decrypts Secret Key
   ( void )Carol.Decrypt( keyCarolC, keyCarolP, length );
   #ifdef _DEBUG
   std::cout << "> Alice sent the Encrypted Secret Key to Carol" << std::endl;
   std::cout << "> Carol Decypts the Secret Key" << std::endl;
   #endif

   elapsedExc = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );

   status = std::memcmp( reinterpret_cast< const void* >( keyBobP ),
                         reinterpret_cast< const void* >( keyCarolP ),
                         bytes );

   start = std::chrono::high_resolution_clock::now( );

   /// -# Encrypt data at Bob and send to Carol
   status = AES::Encrypt( plaintext, size, keyBobP, NULL, ciphertext );
   #ifdef _DEBUG
   std::cout << "> Bob encrypted plaintext and sent ciphertext to Carol" << std::endl;
   #endif

   /// -# Decrypt data at Carol received from Bob
   status = AES::Decrypt( ciphertext, status, keyCarolP, NULL, decrypted );
   #ifdef _DEBUG
   std::cout << "> Carol received ciphertext from Bob and decrypted plaintext" << std::endl;
   #endif

   elapsedCmp = std::chrono::duration_cast< Milliseconds >( HighResClock::now( ) - start ).count( );

   /// -# Verify the decrypted data matches the plaintext
   status = std::memcmp( reinterpret_cast< const void* >( plaintext ), reinterpret_cast< const void* >( decrypted ), status );
   if( status == 0 )
   {
      std::cout << "> SUCCESS: Decrypted text matches plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "> FAILURE: Decrypted text does not match plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }

   std::cout << "> Plaintext Size:        " << size << " Bytes" << std::endl;
   std::cout << "> Key Length:            " << keyLen << " Bits" << std::endl;
   std::cout << "> Secret Key:            " << std::setprecision( 6 ) << elapsedGen << " Milliseconds" << std::endl;
   std::cout << "> Key Distribution:      " << std::setprecision( 6 ) << elapsedExc << " Milliseconds" << std::endl;
   std::cout << "> Encryption/Decryption: " << std::setprecision( 6 ) << elapsedCmp << " Milliseconds" << std::endl;
   std::cout << "> Total:                 " << std::setprecision( 6 )
             << ( elapsedGen + elapsedExc + elapsedCmp ) << " Milliseconds" << std::endl;

   delete rsaKey;
   delete[ ] keyBobP;
   delete[ ] keyBobC;
   delete[ ] keyCarolP;
   delete[ ] keyCarolC;

   std::cout << "Secure Migration (RSA Cryptosystem,AES-256-EBC) END" << std::endl << std::endl;

   return( status );
}
