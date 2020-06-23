#pragma once

#include <Key.h>

namespace SecureMigration
{
   namespace DiffieHellman
   {
      class Session
      {
      private:    // Private Attributes
         Key* params;   ///< Diffie-Hellman Key Exchange Parameters (p,g)
         Key* keyPub;   ///< Diffie-Hellman Public Key
         Key* keyPri;   ///< Diffie-Hellman Private Key
         Key* keySec;   ///< Diffie-Hellman Secret Key;

      public:     // Public Methods
         Session( void );
         ~Session( void );

         Session( const Session& session );
         Session& operator=( const Session& session );

         int Initialize( const Key& params );
         int Derive( const Key& publicKey );

         const Key* PublicKey( void ) const;
         const Key* PrivateKey( void ) const;
         const Key* Secret( void ) const;

         static int GenerateParams( const unsigned int size, Key** params );

      private:    // Private Methods
         void free( void );
      };
   }
}
