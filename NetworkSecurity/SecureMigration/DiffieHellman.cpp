#include <DiffieHellman.h>

#include <openssl/pem.h>
#include <openssl/dh.h>

#include <iostream>

using namespace SecureMigration;
using namespace SecureMigration::DiffieHellman;

Session::Session( void )
{
   this->params = nullptr;
}

Session::~Session( void )
{
   // TODO
}

Session::Session( const Session& session )
{
   *this = session;
}

Session& Session::operator=( const Session& session )
{
   if( this != &session )
   {

   }

   return( *this );
}

int Session::Initialize( const Key& params )
{
   int  status = 0;
   DH*  dh = DH_new( );
   BIO* prmBio;

   this->params = new Key( params );
   
   prmBio = BIO_new( BIO_s_mem( ) );
   BIO_write( prmBio, this->params->Buffer( ), this->params->Length( ) );
   PEM_read_bio_DHparams( prmBio, &dh, NULL, NULL );
   
   const BIGNUM* p = DH_get0_p( dh );
   const BIGNUM* g = DH_get0_g( dh );
   const BIGNUM* a = DH_get0_priv_key( dh );
   const BIGNUM* A = DH_get0_pub_key( dh );

   // Generate the public and private key pair 
   if( 1 != DH_generate_key( dh ) )
   {
      // ERROR
   }
   p = DH_get0_p( dh );
   g = DH_get0_g( dh );
   a = DH_get0_priv_key( dh );
   A = DH_get0_pub_key( dh );

   BIO_free( prmBio );

   return( status );
}

int Session::GenerateParams( const unsigned int size, Key** params )
{
   int status = 0;
   int codes;
   DH* dh;

   unsigned int   prmLen;
   unsigned char* prmBuf;
   BIO* prmBio;

   // Generate the parameters to be used 
   if( ( dh = DH_new( ) ) == NULL )
   {
      status = -1;
   }
   else if( DH_generate_parameters_ex( dh, size, DH_GENERATOR_2, NULL ) != 1 )
   {
      status = -2;
   }
   else if( DH_check( dh, &codes ) != 1 )
   {
      status = -3;
   }
   else if( codes != 0 )
   {
      status = -4;
   }
   else
   {
      prmBio = BIO_new( BIO_s_mem( ) );
      PEM_write_bio_DHparams( prmBio, dh );
      prmLen = BIO_pending( prmBio );
      prmBuf = new unsigned char[ static_cast< unsigned long long >( prmLen ) + 1 ];
      BIO_read( prmBio, prmBuf, prmLen );
      prmBuf[ prmLen ] = '\0';
      BIO_free( prmBio );

      *params = new Key( prmBuf, prmLen );
   }

   return( status );
}

int DiffieHellman::GenerateParams( unsigned int size )
{
   DH* privkey;
   int codes;
   int secret_size;

   unsigned int   prmLen;
   unsigned char* prmBuf;
   BIO*           prmBio = BIO_new( BIO_s_mem( ) );

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

   const BIGNUM* p = DH_get0_p( privkey );
   const BIGNUM* g = DH_get0_g( privkey );
   const BIGNUM* a = DH_get0_priv_key( privkey );
   const BIGNUM* A = DH_get0_pub_key( privkey );

   // Generate the public and private key pair 
   if( 1 != DH_generate_key( privkey ) )
   {
      // ERROR
   }
   // Send the public key to the peer
   // How this occurs will be specific to your situation (see main text below) 

   PEM_write_bio_DHparams( prmBio, privkey );
   
   prmLen = BIO_pending( prmBio );
   prmBuf = new unsigned char[ static_cast< unsigned long long >( prmLen ) + 1 ];
   BIO_read( prmBio, prmBuf, prmLen );
   prmBuf[ prmLen ] = '\0';
   std::cout << prmBuf << std::endl;
   
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
