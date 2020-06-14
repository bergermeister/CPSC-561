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

      public:     // Public Methods
         Session( void );
         ~Session( void );

         Session( const Session& session );
         Session& operator=( const Session& session );

         int Initialize( const Key& params );

         static int GenerateParams( const unsigned int size, Key** params );
      };
      int GenerateParams( unsigned int size );
   }
}
