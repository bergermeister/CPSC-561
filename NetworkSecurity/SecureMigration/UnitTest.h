#pragma once
// Application Includes
#include <Key.h>

// OpenSSL Includes
#include <openssl/bn.h>

namespace SecureMigration
{
   class UnitTest
   {
   private:    // Private Attributes
      const int      BytesPerLineDef = 32;
      int            keySize;
      Key*           dhParams;   ///< Diffie-Hellman Parameters
      Key*           rsaKey;     ///< Secret Key for RSA exchange
      BIGNUM*        prime;
      unsigned char* buffer;

   public:     // Public Methods
      UnitTest( int keySize );
      ~UnitTest( void );

      int Run( void );

   private:    // Private Methods
      UnitTest( const UnitTest& );              // Disabled
      UnitTest& operator=( const UnitTest& );   // Disabled

      int TestDiffieHellman2( int keySize );
      int TestDiffieHellman3( int keySize );
      int TestRSA3( int keySize );
      int TestECB( int size );
      int TestCBC( int size );
   };
}
