// Application Includes
#include <main.h>
#include <Key.h>
#include <RSACryptosystem.h>
#include <DiffieHellman.h>

// OpenSSL Includes
#include <openssl/bn.h>

// StdLib Includes
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace SecureMigration;

static const int BytesPerLineDef = 32;
static Key* dhParams;   ///< Diffie-Hellman Parameters
static Key* rsaKey;     ///< Secret Key for RSA exchange

static int TestDiffieHellman2( int keySize );
static int TestDiffieHellman3( int keySize );
static int TestRSA3( int keySize );
static void PrintHEX( const unsigned char* buffer, int bytes, int bytesPerLine );

int main( int argc, char** argvv )
{
   using HighResClock = std::chrono::high_resolution_clock;
   using Seconds      = std::chrono::duration< double, std::ratio< 1 > >;

   const unsigned int keyLen = 1024;
   int status = 0;
   std::chrono::time_point< HighResClock > start;
   double elapsed;
   BIGNUM*        prime;
   unsigned char* buffer;

   /// @par Process Design Language
   /// -# Generate Diffie-Hellman Parameters
   DiffieHellman::Session::GenerateParams( keyLen, &dhParams );

   /// -# Generate shared secret for RSA exchange
   buffer = new unsigned char[ ( keyLen + 7 ) / 8 ];
   prime = BN_generate_prime( NULL, keyLen, 1, NULL, NULL, NULL, NULL );
   BN_bn2bin( prime, buffer );
   rsaKey = new Key( buffer, ( keyLen + 7 ) / 8 );

   /// -# Test Diffie-Hellman Shared Secret with 2 Participants
   std::cout << "Executing Diffie-Hellman Shared Secret Exchange with 2 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestDiffieHellman2( keyLen );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test Diffie-Hellman Shared Secret with 3 Participants
   std::cout << "Executing Diffie-Hellman Shared Secret Exchange with 3 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestDiffieHellman3( keyLen );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   /// -# Test RSA Shared Secret with 3 Participants
   std::cout << "Executing RSA Shared Secret Exchange with 3 Participants" << std::endl;
   start = std::chrono::high_resolution_clock::now( );
   status |= TestRSA3( keyLen );
   elapsed = std::chrono::duration_cast< Seconds >( HighResClock::now( ) - start ).count( );
   std::cout << std::endl << "Elapsed: " << std::setprecision( 6 ) << elapsed << " Seconds" << std::endl << std::endl;

   delete dhParams;
   delete[ ] buffer;
   BN_free( prime );

   return( status );
}

static int TestDiffieHellman2( int keySize )
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
      PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice derived shared secret:" << std::endl;
      PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Bob derived shared secret:" << std::endl;
      PrintHEX( Bob.Secret( )->Buffer( ), Bob.Secret( )->Length( ), BytesPerLineDef );
   }

   return( status );
}

static int TestDiffieHellman3( int keySize )
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
      PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice derived shared secret:" << std::endl;
      PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Bob derived shared secret:" << std::endl;
      PrintHEX( Bob.Secret( )->Buffer( ), Bob.Secret( )->Length( ), BytesPerLineDef );

      std::cout << "Carol derived shared secret:" << std::endl;
      PrintHEX( Carol.Secret( )->Buffer( ), Carol.Secret( )->Length( ), BytesPerLineDef );
   }

   delete keyGab;
   delete keyGac;
   delete keyGbc;

   return( status );
}

static int TestRSA3( int keySize )
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
      PrintHEX( plaintextA, bytes, BytesPerLineDef );
   }
   else
   {
      std::cout << "Alice created Shared Secret" << std::endl;
      PrintHEX( plaintextA, bytes, BytesPerLineDef );
      std::cout << "Bob obtained Shared Secret" << std::endl;
      PrintHEX( plaintextB, bytes, BytesPerLineDef );
      std::cout << "Carol obtained Shared Secret" << std::endl;
      PrintHEX( plaintextC, bytes, BytesPerLineDef );
   }

   delete[ ] plaintextA;
   delete[ ] plaintextB;
   delete[ ] plaintextC;
   delete[ ] ciphertext;

   return( status );
}

static void PrintHEX( const unsigned char* buffer, int bytes, int bytesPerLine )
{
   const char map[ ] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
   int offset;
   int limit = bytesPerLine - 1;

   for( offset = 0; offset < bytes; offset++ )
   {
      std::cout << map[ ( buffer[ offset ] >> 4 ) & 0x0F ] << map[ buffer[ offset ] & 0x04 ];
      if( ( offset % bytesPerLine ) == limit )
      {
         std::cout << std::endl;
      }
   }

   if( ( offset % bytesPerLine ) == 0 )
   {
      std::cout << std::endl;
   }
}

