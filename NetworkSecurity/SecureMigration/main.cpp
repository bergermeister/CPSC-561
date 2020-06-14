#include <main.h>
#include <Key.h>
#include <RSACryptosystem.h>

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
   //Key* keyPub;
   //Key* keyPri;
   RSACryptosystem::Cipher cipher;

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
   else if( ( length = cipher.Encrypt( plaintext, ciphertext, strlen( ( const char* )plaintext ), *cipher.PublicKey( ) ) ) < 0 )
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

