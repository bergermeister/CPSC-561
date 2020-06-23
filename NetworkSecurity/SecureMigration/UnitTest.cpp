// Application Includes
#include <UnitTest.h>
#include <Utility.h>
#include <DiffieHellman.h>
#include <RSACryptosystem.h>
#include <AES.h>

// OpenSSL Includes
#include <openssl/bn.h>

// StdLib Includes
#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace SecureMigration;

UnitTest::UnitTest( int keySize )
{
   /// -# Record Key Size
   this->keySize = keySize;

   /// -# Generate Diffie-Hellman Parameters
   DiffieHellman::Session::GenerateParams( keySize, &dhParams );

   /// -# Generate shared secret for RSA exchange
   buffer = new unsigned char[ ( keySize + 7 ) / 8 ];
   prime = BN_generate_prime( NULL, keySize, 1, NULL, NULL, NULL, NULL );
   BN_bn2bin( prime, buffer );
   rsaKey = new Key( buffer, ( keySize + 7 ) / 8 );
}

UnitTest::~UnitTest( void )
{
   delete this->dhParams;
   delete this->rsaKey;
   BN_free( this->prime );
}

int UnitTest::Run( void )
{
   using HighResClock = std::chrono::high_resolution_clock;
   using Seconds = std::chrono::duration< double, std::ratio< 1 > >;
   
   int status = 0;
   std::chrono::time_point< HighResClock > start;
   double elapsed;

   /// @par Process Design Language
   /// -# Test Diffie-Hellman Shared Secret with 2 Participants
   std::cout << "Executing Diffie-Hellman Shared Secret Exchange with 2 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestDiffieHellman2( this->keySize );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test Diffie-Hellman Shared Secret with 3 Participants
   std::cout << "Executing Diffie-Hellman Shared Secret Exchange with 3 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestDiffieHellman3( this->keySize );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test RSA Shared Secret with 3 Participants
   std::cout << "Executing RSA Shared Secret Exchange with 3 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestRSA3( this->keySize );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << std::endl << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test AES ECB
   std::cout << "Executing AES ECB" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestECB( this->keySize );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << std::endl << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test AES ECB
   std::cout << "Executing AES CBC" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestCBC( this->keySize );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << std::endl << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   return( status );
}

int UnitTest::TestDiffieHellman2( int keySize )
{
   int status = 0;

   DiffieHellman::Session Alice;
   DiffieHellman::Session Bob;

   /// -# Distribute Diffie-Hellman Parameters to all clients
   Alice.Initialize( *dhParams );
   Bob.Initialize( *dhParams );

   /// -# Derive Shared Secrets
   Alice.Derive( *Bob.PublicKey( ) );
   Bob.Derive( *Alice.PublicKey( ) );

   /// -# Verify the Shared Secrets Match
   if( *Alice.Secret( ) == *Bob.Secret( ) )
   {
      std::cout << "Alice and Bob derived shared secret:" << std::endl;
      Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice derived shared secret:" << std::endl;
      Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Bob derived shared secret:" << std::endl;
      Utility::PrintHEX( Bob.Secret( )->Buffer( ), Bob.Secret( )->Length( ), BytesPerLineDef );
   }

   return( status );
}

int UnitTest::TestDiffieHellman3( int keySize )
{
   int status = 0;
   DiffieHellman::Session Alice;
   DiffieHellman::Session Bob;
   DiffieHellman::Session Carol;
   Key*                   keyGab;
   Key*                   keyGac;
   Key*                   keyGbc;

   /// @par Process Design Language
   /// -# Distribute Diffie-Hellman Parameters to all clients
   Alice.Initialize( *dhParams );
   Bob.Initialize( *dhParams );
   Carol.Initialize( *dhParams );

   /// -# Derive Intermediate Public Key
   Bob.Derive( *Alice.PublicKey( ) );
   keyGab = new Key( *Bob.Secret( ) );
   Carol.Derive( *Alice.PublicKey( ) );
   keyGac = new Key( *Carol.Secret( ) );
   Carol.Derive( *Bob.PublicKey( ) );
   keyGbc = new Key( *Carol.Secret( ) );

   /// -# Derive Shared Secrets
   Alice.Derive( *keyGbc );
   Bob.Derive( *keyGac );
   Carol.Derive( *keyGab );

   /// -# Verify the Shared Secrets Match
   if( ( *Alice.Secret( ) == *Bob.Secret( ) ) && ( *Alice.Secret( ) == *Carol.Secret( ) ) )
   {
      std::cout << "Alice, Bob, and Carol derived shared secret:" << std::endl;
      Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice derived shared secret:" << std::endl;
      Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Bob derived shared secret:" << std::endl;
      Utility::PrintHEX( Bob.Secret( )->Buffer( ), Bob.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Carol derived shared secret:" << std::endl;
      Utility::PrintHEX( Carol.Secret( )->Buffer( ), Carol.Secret( )->Length( ), BytesPerLineDef );
   }

   delete keyGab;
   delete keyGac;
   delete keyGbc;

   return( status );
}

int UnitTest::TestRSA3( int keySize )
{
   int status = 0;
   unsigned char* plaintextA = new unsigned char[ keySize ];
   unsigned char* plaintextB = new unsigned char[ keySize ];
   unsigned char* plaintextC = new unsigned char[ keySize ];
   unsigned char* ciphertext = new unsigned char[ keySize ];
   int            bytes = ( ( keySize + 7 ) / 8 ) - 11;
   int            length;

   RSACryptosystem::Cipher Alice;
   RSACryptosystem::Cipher Bob;
   RSACryptosystem::Cipher Carol;

   /// @par Process Design Language
   /// -# Clear buffers
   std::memset( reinterpret_cast< void* >( plaintextA ), 0, keySize );
   std::memset( reinterpret_cast< void* >( plaintextB ), 0, keySize );
   std::memset( reinterpret_cast< void* >( plaintextB ), 0, keySize );
   std::memset( reinterpret_cast< void* >( ciphertext ), 0, keySize );

   /// -# Initialize Plaintext for Alice
   std::memcpy( reinterpret_cast< void* >( plaintextA ),
      reinterpret_cast< const void* >( rsaKey->Buffer( ) ),
      rsaKey->Length( ) );

   /// -# Generate Public/Private Key Pair
   Alice.Initialize( keySize );
   Bob.Initialize( keySize );
   Carol.Initialize( keySize );

   /// -# Alice shares secret with Bob
   ///   -# Alice encrypts plaintext with Bob's Public Key
   ///   -# Alice sends ciphertext to Bob
   ///   -# Bob decrypts ciphertext to obtain shared secret
   length = Alice.Encrypt( plaintextA, ciphertext, bytes, *Bob.PublicKey( ) );
   Bob.Decrypt( ciphertext, plaintextB, length );

   /// -# Alice shares secret with Carol
   ///   -# Alice encrypts plaintext with Carol's Public Key
   ///   -# Alice sends ciphertext to Carol
   ///   -# Carol decrypts ciphertext to obtain shared secret
   length = Alice.Encrypt( plaintextA, ciphertext, bytes, *Carol.PublicKey( ) );
   Carol.Decrypt( ciphertext, plaintextC, length );

   if( ( std::memcmp( plaintextA, plaintextB, bytes ) == 0 ) &&
       ( std::memcmp( plaintextA, plaintextC, bytes ) == 0 ) )
   {
      std::cout << "Alice, Bob, and Carol obtained the same Shared Secret" << std::endl;
      Utility::PrintHEX( plaintextA, bytes, BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice created Shared Secret" << std::endl;
      Utility::PrintHEX( plaintextA, bytes, BytesPerLineDef );
      std::cout << "Bob obtained Shared Secret" << std::endl;
      Utility::PrintHEX( plaintextB, bytes, BytesPerLineDef );
      std::cout << "Carol obtained Shared Secret" << std::endl;
      Utility::PrintHEX( plaintextC, bytes, BytesPerLineDef );
   }

   delete[ ] plaintextA;
   delete[ ] plaintextB;
   delete[ ] plaintextC;
   delete[ ] ciphertext;

   return( status );
}

int UnitTest::TestECB( int size )
{
   unsigned char  key[ ] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
   unsigned char* plaintext = new unsigned char[ size * 2 ];
   unsigned char* ciphertext = new unsigned char[ size * 2 ];
   unsigned char* decrypted = new unsigned char[ size * 2 ];

   int status = 0;
   int len;

   /// @par Process Design Language
   /// -# Initialize plaintext
   for( int i = 0; i < size; i++ )
   {
      plaintext[ i ] = static_cast< unsigned char >( i );
   }

   len = AES::Encrypt( plaintext, size, key, NULL, ciphertext );
   len = AES::Decrypt( ciphertext, len, key, NULL, decrypted );

   status = std::memcmp( reinterpret_cast< const void* >( plaintext ), reinterpret_cast< const void* >( decrypted ), len );

   delete[ ] plaintext;
   delete[ ] ciphertext;
   delete[ ] decrypted;

   return( status );
}

int UnitTest::TestCBC( int size )
{
   unsigned char  key[ ] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
   unsigned char  iv[ ] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
   unsigned char* plaintext = new unsigned char[ size * 2 ];
   unsigned char* ciphertext = new unsigned char[ size * 2 ];
   unsigned char* decrypted = new unsigned char[ size * 2 ];

   int status = 0;
   int len;

   /// @par Process Design Language
   /// -# Initialize plaintext
   for( int i = 0; i < size; i++ )
   {
      plaintext[ i ] = static_cast< unsigned char >( i );
   }

   len = AES::Encrypt( plaintext, size, key, iv, ciphertext );
   len = AES::Decrypt( ciphertext, len, key, iv, decrypted );

   status = std::memcmp( reinterpret_cast< const void* >( plaintext ), reinterpret_cast< const void* >( decrypted ), len );

   delete[ ] plaintext;
   delete[ ] ciphertext;
   delete[ ] decrypted;

   return( status );
}
