#pragma once

namespace SecureMigration
{
   namespace AES
   {
      int Encrypt( const unsigned char* plaintext,  int pLen, const unsigned char* key, 
                   const unsigned char* iv, unsigned char* ciphertext );
      int Decrypt( const unsigned char* ciphertext, int cLen, const unsigned char* key, 
                   const unsigned char* iv, unsigned char* plaintext );
   }
}

