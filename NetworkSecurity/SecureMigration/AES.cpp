// Application Includes
#include <AES.h>

// OpenSSL Includes
#include <openssl/evp.h>

using namespace SecureMigration;

int AES::Encrypt( const unsigned char* plaintext, int pLen, const unsigned char* key, 
                  const unsigned char* iv, unsigned char* ciphertext )
{
   int                  status = 0;
   EVP_CIPHER_CTX*      context = NULL;
   const EVP_CIPHER*    cipher   = ( iv == NULL ) ? EVP_aes_256_ecb( ) : EVP_aes_256_cbc( );
   const unsigned char* bufferIV = ( iv == NULL ) ? NULL : iv;
   
   int encryptedLen;
   int ciphertextLen;

   /// @par Process Design Language
   /// -# Create and initialise the context 
   if( ( context = EVP_CIPHER_CTX_new( ) ) == NULL )
   {
      status = -1;
   }
   /// -# Initialise the encryption operation
   else if( EVP_EncryptInit_ex( context, cipher, NULL, key, bufferIV ) != 1 )
   {
      status = -2;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Encrypt the message
   else if( EVP_EncryptUpdate( context, ciphertext, &encryptedLen, plaintext, pLen ) != 1 )
   {
      status = -3;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Finalize the encryption
   else if( EVP_EncryptFinal_ex( context, ciphertext + encryptedLen, &ciphertextLen ) != 1 )
   {
      status = -4;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Cleanup
   else
   {
      status = ciphertextLen + encryptedLen;
      EVP_CIPHER_CTX_free( context );
   }

   return( status );
}

int AES::Decrypt( const unsigned char* ciphertext, int cLen, const unsigned char* key, 
                  const unsigned char* iv, unsigned char* plaintext )
{
   int                  status = 0;
   EVP_CIPHER_CTX*      context = NULL;
   const EVP_CIPHER*    cipher = ( iv == NULL ) ? EVP_aes_256_ecb( ) : EVP_aes_256_cbc( );
   const unsigned char* bufferIV = ( iv == NULL ) ? NULL : iv;

   int decryptedLen;
   int plaintextLen;

   /// @par Process Design Language
   /// -# Create and initialise the context 
   if( ( context = EVP_CIPHER_CTX_new( ) ) == NULL )
   {
      status = -1;
   }
   /// -# Initialise the decryption operation
   else if( EVP_DecryptInit_ex( context, cipher, NULL, key, bufferIV ) != 1 )
   {
      status = -2;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Decrypt the message
   else if( EVP_DecryptUpdate( context, plaintext, &decryptedLen, ciphertext, cLen ) != 1 )
   {
      status = -3;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Finalize the Decrypt
   else if( EVP_DecryptFinal_ex( context, plaintext + decryptedLen, &plaintextLen ) != 1 )
   {
      status = -4;
      EVP_CIPHER_CTX_free( context );
   }
   /// -# Cleanup
   else
   {
      status = plaintextLen + decryptedLen;
      EVP_CIPHER_CTX_free( context );
   }

   return( status );
}
