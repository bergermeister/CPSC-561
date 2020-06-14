#pragma once

#include <Key.h>

namespace SecureMigration
{
   namespace RSACryptosystem
   {
      int GenerateKeyPair( unsigned int keySize, Key** keyPub, Key** keyPri );
      int Encrypt( const unsigned char* plaintext, unsigned char* ciphertext, int length, const Key& keyPub );
      int Decrypt( const unsigned char* ciphertext, unsigned char* plaintext, int length, const Key& keyPri );
   };
}

