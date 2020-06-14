#include <DiffieHellman.h>

#include <openssl/pem.h>
#include <openssl/dh.h>

using namespace SecureMigration;

int DiffieHellman::GenerateParams( unsigned int size )
{
   DH* privkey;
   int codes;
   int secret_size;

   // Generate the parameters to be used 
   if( ( privkey = DH_new( ) ) == NULL )
   {
      // ERROR
   }
   else if( DH_generate_parameters_ex( privkey, 2048, DH_GENERATOR_2, NULL ) != 1 )
   {
      // ERROR
   }
   else if( DH_check( privkey, &codes ) != 1 )
   {
      // ERROR
   }
   else if( codes != 0 )
   {
      // Problems have been found with the generated parameters 
      // Handle these here - we'll just abort for this example 
      printf( "DH_check failed\n" );
      abort( );
   }
   // Generate the public and private key pair 
   else if( 1 != DH_generate_key( privkey ) )
   {
      // ERROR
   }
   // Send the public key to the peer
   // How this occurs will be specific to your situation (see main text below) 


    /* Receive the public key from the peer. In this example we're just hard coding a value */
   BIGNUM* pubkey = NULL;
   if( 0 == ( BN_dec2bn( &pubkey, "01234567890123456789012345678901234567890123456789" ) ) )
   {
      // ERROR
   }

   /* Compute the shared secret */
   unsigned char* secret;
   if( NULL == ( secret = ( unsigned char* )OPENSSL_malloc( sizeof( unsigned char ) * ( DH_size( privkey ) ) ) ) )
   {
      // ERROR
   }
   else if( 0 > ( secret_size = DH_compute_key( secret, pubkey, privkey ) ) )
   {
      // ERROR
   }

   // Do something with the shared secret 
   // Note secret_size may be less than DH_size(privkey) 
   printf( "The shared secret is:\n" );
   BIO_dump_fp( stdout, ( const char* )secret, secret_size );

   // Clean up 
   OPENSSL_free( secret );

   BN_free( pubkey );
   DH_free( privkey );
}
