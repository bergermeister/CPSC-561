#include <main.h>
#include <Key.h>
#include <RSACryptosystem.h>
#include <DiffieHellman.h>

#include <iostream>
using namespace SecureMigration;

int main( int argc, char** argvv )
{
   const unsigned int keyLen = 2048;
   int status = 0;
   const unsigned char plaintext[ keyLen ] = "Hello World!";
   unsigned char       ciphertext[ keyLen ];
   unsigned char       result[ keyLen ];
   int                 length;
   RSACryptosystem::Cipher cipher;


   DiffieHellman::Session Alice;
   DiffieHellman::Session Bob;
   DiffieHellman::Session Carol;
   Key*                   params;
   Key*                   keyGab;
   Key*                   keyGac;
   Key*                   keyGbc;

   /// -# Generate Diffie-Hellman Parameters
   DiffieHellman::Session::GenerateParams( 1024, &params );

   /// -# Distribute Diffie-Hellman Parameters to all clients
   Alice.Initialize( *params );
   Bob.Initialize( *params );
   Carol.Initialize( *params );

   /// -# Simple example of Alice and Bob Sharing a Key
   Alice.Derive( *Bob.PublicKey( ) );
   Bob.Derive( *Alice.PublicKey( ) );
   if( *Alice.Secret( ) == *Bob.Secret( ) )
   {
      std::cout << "Alice and Bob exchange secret keys:" << std::endl;
      std::cout << Alice.Secret( )->Buffer( ) << std::endl;
      std::cout << Bob.Secret( )->Buffer( ) << std::endl;
   }

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

   if( ( *Alice.Secret( ) == *Bob.Secret( ) ) && ( *Alice.Secret( ) == *Carol.Secret( ) ) )
   {
      std::cout << Alice.Secret( )->Buffer( ) << std::endl;
      std::cout << Bob.Secret( )->Buffer( ) << std::endl;
      std::cout << Carol.Secret( )->Buffer( ) << std::endl;
   }

   /// @par Process Design Language
   /// -# Clear buffers
   std::memset( reinterpret_cast< void* >( ciphertext ), 0, keyLen );
   std::memset( reinterpret_cast< void* >( result ), 0, keyLen );

   /// -# Generate Public/Private Key Pair
   if( cipher.Initialize( keyLen ) != 0 )
   {
      status = 1;
   }
   /// -# Encrypt plaintext
   else if( ( length = cipher.Encrypt( plaintext, ciphertext, ( size_t )strlen( ( const char* )plaintext ), *cipher.PublicKey( ) ) ) < 0 )
   {
      status = 2;
   }
   /// -# Decrypt ciphertext
   else if( ( length = cipher.Decrypt( ciphertext, result, length ) ) < 0 )
   {
      status = 3;
   }

   /// -# Print components
   std::cout << "Plaintext: " << std::endl << plaintext << std::endl;
   std::cout << "Ciphertext: " << std::endl << ciphertext << std::endl;
   std::cout << "Decrypted: " << std::endl << result << std::endl;

   return( status );
}

