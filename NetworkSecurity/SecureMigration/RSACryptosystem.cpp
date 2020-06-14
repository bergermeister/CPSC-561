// Application Includes
#include <Key.h>
#include <RSACryptosystem.h>

// openssl Includes
#include <openssl/rsa.h>
#include <openssl/pem.h>

using namespace SecureMigration;
using namespace SecureMigration::RSACryptosystem;

/*
int RSACryptosystem::GenerateKeyPair( unsigned int keySize, Key** keyPub, Key** keyPri )
{
   int status = 0;
 
   unsigned int   priLen;
   unsigned char* priBuf;
   BIO*           priBio = BIO_new( BIO_s_mem( ) );
   unsigned int   pubLen;
   unsigned char* pubBuf;
   BIO*           pubBio = BIO_new( BIO_s_mem( ) );
   RSA*           keyPair;

   // Generate Key Pair
   keyPair = RSA_generate_key( keySize, 3, NULL, NULL );
   PEM_write_bio_RSAPrivateKey( priBio, keyPair, NULL, NULL, 0, NULL, NULL );
   priLen = BIO_pending( priBio );
   priBuf = new unsigned char[ priLen +1 ];
   BIO_read( priBio, priBuf, priLen );
   priBuf[ priLen ] = '\0';

   PEM_write_bio_RSAPublicKey( pubBio, keyPair );
   pubLen = BIO_pending( pubBio );
   pubBuf = new unsigned char[ pubLen + 1 ];
   BIO_read( pubBio, pubBuf, pubLen );
   pubBuf[ pubLen ] = '\0';

   *keyPub = new Key( pubBuf, pubLen );
   *keyPri = new Key( priBuf, priLen );

   return( status );
}
*/

int RSACryptosystem::GenerateKeyPair( unsigned int keySize, Key** keyPub, Key** keyPri )
{
   int           status = 0;
   EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL );
   EVP_PKEY*     keyPair = NULL;

   unsigned int   priLen;
   unsigned char* priBuf;
   BIO* priBio = BIO_new( BIO_s_mem( ) );
   unsigned int   pubLen;
   unsigned char* pubBuf;
   BIO* pubBio = BIO_new( BIO_s_mem( ) );

   /// -# Initialize key generation context
   if( EVP_PKEY_keygen_init( context ) <= 0 )
   {
      status = -1;
   }
   /// -# Set the number of bits for the rsa keygen
   else if( EVP_PKEY_CTX_set_rsa_keygen_bits( context, keySize ) <= 0 )
   {
      status = -2;
   }
   /// -# Generate key pair
   else if( EVP_PKEY_keygen( context, &keyPair ) <= 0 )
   {
      status = -3;
   }
   else
   {
      PEM_write_bio_PrivateKey( priBio, keyPair, NULL, NULL, NULL, NULL, NULL );
      priLen = BIO_pending( priBio );
      priBuf = new unsigned char[ static_cast< unsigned long long >( priLen ) + 1 ];
      BIO_read( priBio, priBuf, priLen );
      priBuf[ priLen ] = '\0';

      PEM_write_bio_PUBKEY( pubBio, keyPair );
      pubLen = BIO_pending( pubBio );
      pubBuf = new unsigned char[ static_cast< unsigned long long >( pubLen ) + 1 ];
      BIO_read( pubBio, pubBuf, pubLen );
      pubBuf[ pubLen ] = '\0';
      
      *keyPub = new Key( pubBuf, pubLen );
      *keyPri = new Key( priBuf, priLen );
   }

   EVP_PKEY_CTX_free( context );

   return( status );
}


int RSACryptosystem::Encrypt( const unsigned char* plaintext, unsigned char* ciphertext, int length, const Key& keyPub )
{
   int status = 0;
   
   BIO* key = NULL;
   RSA* rsa = NULL;
   
   if( ( key = BIO_new_mem_buf( keyPub.Buffer( ), -1 ) ) == NULL )
   {
      status = -1;
   }
   else if( ( rsa = PEM_read_bio_RSA_PUBKEY( key, &rsa, NULL, NULL ) ) == NULL )
   {
      status = -2;
      BIO_free( key );
   }
   else
   {
      status = RSA_public_encrypt( length, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING );
      BIO_free( key );
      RSA_free( rsa );
   }

   return( status );
}

int RSACryptosystem::Decrypt( const unsigned char* ciphertext, unsigned char* plaintext, int length, const Key& keyPri )
{
   int status = 0;

   BIO* key = nullptr;
   RSA* rsa = nullptr;

   if( ( key = BIO_new_mem_buf( keyPri.Buffer( ), -1 ) ) == NULL )
   {
      status = -1;
   }
   else if( ( rsa = PEM_read_bio_RSAPrivateKey( key, &rsa, NULL, NULL ) ) == NULL )
   {
      status = -2;
      BIO_free( key );
   }
   else
   {
      status = RSA_private_decrypt( length, ciphertext, plaintext, rsa, RSA_PKCS1_PADDING );
      BIO_free( key );
      RSA_free( rsa );
   }

   return( status );
}

