// Application Includes
#include <Simulation.h>
#include <Utility.h>
#include <DiffieHellman.h>
#include <AES.h>

// StdLib Includes
#include <iostream>

using namespace SecureMigration;

int Simulation::RunDiffieHellman( const unsigned char* plaintext, int size )
{
   const int BytesPerLineDef = 32;
   const int keySize = 1024;
   int status = 0;
   unsigned char* ciphertext = new unsigned char[ size + 32 ];
   unsigned char* decrypted = new unsigned char[ size + 32 ];

   DiffieHellman::Session Alice;
   DiffieHellman::Session Bob;
   DiffieHellman::Session Carol;
   Key* keyGab;
   Key* keyGac;
   Key* keyGbc;
   Key* dhParams;

   /// @par Process Design Language
   /// -# Generate Diffie-Hellman Parameters
   DiffieHellman::Session::GenerateParams( keySize, &dhParams );
   Alice.Initialize( *dhParams );
   std::cout << "> Alice Generated Diffie-Hellman Parameters" << std::endl;

   /// -# Distribute Diffie-Hellman Parameters to all clients
   Bob.Initialize( *dhParams );
   Carol.Initialize( *dhParams );
   std::cout << "> Alice distributed Diffie-Hellman Parameters to Bob and Carol" << std::endl;

   /// -# Derive Intermediate Public Key
   Bob.Derive( *Alice.PublicKey( ) );
   keyGab = new Key( *Bob.Secret( ) );
   std::cout << "> Alice sent her Public Key to Bob" << std::endl;
   std::cout << "> Bob calculated intermediate public key g^ab" << std::endl;
   Carol.Derive( *Alice.PublicKey( ) );
   keyGac = new Key( *Carol.Secret( ) );
   std::cout << "> Alice sent her Public Key to Carol" << std::endl;
   std::cout << "> Carol calculated intermediate public key g^ac" << std::endl;
   Carol.Derive( *Bob.PublicKey( ) );
   keyGbc = new Key( *Carol.Secret( ) );
   std::cout << "> Bob sent his Public Key to Carol" << std::endl;
   std::cout << "> Carol calculated intermediate public key g^bc" << std::endl;

   /// -# Derive Shared Secrets
   Alice.Derive( *keyGbc );
   std::cout << "> Carol sent intermediate public key g^bc to Alice" << std::endl;
   std::cout << "> Alice Derived the Shared Secret" << std::endl;
   Bob.Derive( *keyGac );
   std::cout << "> Carol sent intermediate public key g^ac to Bob" << std::endl;
   std::cout << "> Bob Derived the Shared Secret" << std::endl;
   Carol.Derive( *keyGab );
   std::cout << "> Bob sent intermediate public key g^ab to Carol" << std::endl;
   std::cout << "> Carol Derived the Shared Secret" << std::endl;

   /// -# Delete Intermediate Keys after use
   delete keyGab;
   delete keyGac;
   delete keyGbc;

   /// -# Encrypt data at Bob and send to Carol
   status = AES::Encrypt( plaintext, size, Bob.Secret( )->Buffer( ), &Bob.Secret( )->Buffer( )[ 32 ], ciphertext );
   std::cout << "> Bob encrypted plaintext and sent ciphertext to Carol" << std::endl;

   /// -# Decrypt data at Carol received from Bob
   status = AES::Decrypt( ciphertext, status, Carol.Secret( )->Buffer( ), &Carol.Secret( )->Buffer( )[ 32 ], decrypted );
   std::cout << "> Carol received ciphertext from Bob and decrypted plaintext" << std::endl;

   /// -# Verify the decrypted data matches the plaintext
   status = std::memcmp( reinterpret_cast< const void* >( plaintext ), reinterpret_cast< const void* >( decrypted ), status );
   if( status == 0 )
   {
      std::cout << "SUCCESS: Decrypted text matches plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }
   else
   {
      std::cout << "FAILURE: Decrypted text does not match plaintext" << std::endl;
      //Utility::PrintHEX( Alice.Secret( )->Buffer( ), Alice.Secret( )->Length( ), BytesPerLineDef );
   }

   delete[ ] ciphertext;
   delete[ ] decrypted;

   return( status );
}

int Simulation::RunRSA( const unsigned char* plaintext, int size )
{
   int status = 0;

   return( status );
}
