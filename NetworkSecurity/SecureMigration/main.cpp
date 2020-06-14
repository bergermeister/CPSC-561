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
   Key* keyPub;
   Key* keyPri;

   /// @par Process Design Language
   /// -# Clear buffers
   std::memset( reinterpret_cast< void* >( ciphertext ), 0, keyLen );
   std::memset( reinterpret_cast< void* >( result ), 0, keyLen );

   /// -# Generate Public/Private Key Pair
   RSACryptosystem::GenerateKeyPair( keyLen, &keyPub, &keyPri );

   /// -# Encrypt plaintext
   length = RSACryptosystem::Encrypt( plaintext, ciphertext, 13, *keyPub );

   /// -# Decrypt ciphertext
   length = RSACryptosystem::Decrypt( ciphertext, result, length, *keyPri );

   /// -# Print components
   std::cout << keyPub->Buffer( ) << std::endl;
   std::cout << keyPri->Buffer( ) << std::endl;
   std::cout << "Plaintext: " << std::endl << plaintext << std::endl;
   std::cout << "Ciphertext: " << std::endl << ciphertext << std::endl;
   std::cout << "Decrypted: " << std::endl << result << std::endl;

   /// -# Free allocated memory
   delete keyPub;
   delete keyPri;

   return( status );
}

