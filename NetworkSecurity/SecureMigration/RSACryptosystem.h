#pragma once

#include <Key.h>

namespace SecureMigration
{
   namespace RSACryptosystem
   {
      class Cipher
      {
      private:    // Private Attributes
         Key* keyPublic;    ///< Public Key
         Key* keyPrivate;   ///< Private Key

      public:     // Public Methods
         Cipher( void );
         ~Cipher( void );

         Cipher( const Cipher& cipher );
         Cipher& operator=( const Cipher& cipher );

         int Initialize( unsigned int keySize );
         int Encrypt( const unsigned char* plaintext, unsigned char* ciphertext, int length, const Key& keyPub );
         int Decrypt( const unsigned char* ciphertext, unsigned char* plaintext, int length );
         int Sign( const unsigned char* plaintext, unsigned char* ciphertext, int length );
         int Verify( const unsigned char* ciphertext, unsigned char* plaintext, int length, const Key& keyPub );

         const Key* PublicKey( void ) const;

      private:    // Private Methods
         void free( void );
      };
   };
}

