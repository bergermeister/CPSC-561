#include <DiffieHellman.h>

#include <openssl/pem.h>
#include <openssl/dh.h>

#include <iostream>

using namespace SecureMigration;
using namespace SecureMigration::DiffieHellman;

static DH* getDH( const Key& params );

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
   DH*  dh;
   int            keyLen;
   unsigned char* keyBuf;

   /// @par Process Design Language
   /// -# Store the raw Diffie-Hellman Parameters (p&g)
   this->params = new Key( params );

   /// -# Get Diffie-Hellman instance
   dh = getDH( *this->params );

   /// -# Generate the public and private key pair 
   if( 1 != DH_generate_key( dh ) )
   {
      // ERROR
      status = -1;
   }
   else
   {
      /// -# Extract Public Key
      keyLen = BN_num_bytes( DH_get0_pub_key( dh ) );
      keyBuf = new unsigned char[ static_cast< unsigned long long >( keyLen ) + 1 ];
      keyBuf[ keyLen ] = '\0';
      BN_bn2bin( DH_get0_pub_key( dh ), keyBuf );
      this->keyPub = new Key( keyBuf, keyLen );

      /// -# Extract Private Key
      keyLen = BN_num_bytes( DH_get0_priv_key( dh ) );
      keyBuf = new unsigned char[ static_cast< unsigned long long >( keyLen ) + 1 ];
      keyBuf[ keyLen ] = '\0';
      BN_bn2bin( DH_get0_priv_key( dh ), keyBuf );
      this->keyPri = new Key( keyBuf, keyLen );
   }

   //const BIGNUM* p = DH_get0_p( dh );
   //const BIGNUM* g = DH_get0_g( dh );
   //const BIGNUM* a = DH_get0_priv_key( dh );
   //const BIGNUM* A = DH_get0_pub_key( dh );
   //BIGNUM* a;
   //a = BN_bin2bn( this->keyPri->Buffer( ), this->keyPri->Length( ), NULL );
   //int res = BN_cmp( DH_get0_priv_key( dh ), a );
   //BN_free( a );

   return( status );
}

int Session::Derive( const Key& publicKey )
{
   int            status = 0;
   int            keyLen;
   unsigned char* keyBuf;
   DH*            dh = NULL;
   BIGNUM*        a;  // Local  Private Key
   BIGNUM*        A;  // Local  Public Key
   BIGNUM*        B;  // Remote Public key

   /// @par Process Design Language
   /// -# Convert Private Key and Public Key to BIGNUMs
   a = BN_bin2bn( this->keyPri->Buffer( ), this->keyPri->Length( ), NULL );
   A = BN_bin2bn( this->keyPub->Buffer( ), this->keyPub->Length( ), NULL );
   B = BN_bin2bn( publicKey.Buffer( ), publicKey.Length( ), NULL );

   /// -# Get Diffie-Hellman instance
   dh = getDH( *this->params );

   if( dh == NULL )
   {
      status = -1;
   }
   else if( NULL == ( keyBuf = ( unsigned char* )OPENSSL_malloc( sizeof( unsigned char ) * ( DH_size( dh ) + 1 ) ) ) )
   {
      status = -2;
      DH_free( dh );
   }
   else if( DH_set0_key( dh, A, a ) != 1 )
   {
      status = -3;
      DH_free( dh );
   }
   else
   {
      keyLen = DH_compute_key( keyBuf, B, dh );
      keyBuf[ keyLen + 1 ] = '\0';
      DH_free( dh );
      this->keySec = new Key( keyBuf, keyLen );
   }

   /// -# Free allocated memory for a and B
   BN_free( a );
   BN_free( B );

   return( status );
}

const Key* Session::PublicKey( void ) const
{
   return( this->keyPub );
}

const Key* Session::PrivateKey( void ) const
{
   return( this->keyPri );
}

const Key* Session::Secret( void ) const
{
   return( this->keySec );
}

int Session::GenerateParams( const unsigned int size, Key** params )
{
   int status = 0;
   int codes;
   DH* dh;

   unsigned int   prmLen;
   unsigned char* prmBuf;
   BIO* prmBio;

   /// @par Process Design Language
   /// -# Create new DH structure
   if( ( dh = DH_new( ) ) == NULL )
   {
      status = -1;
   }
   /// -# Generate DH parameters
   else if( DH_generate_parameters_ex( dh, size, DH_GENERATOR_2, NULL ) != 1 )
   {
      status = -2;
      DH_free( dh );
   }
   /// -# Verify DH parameters are valid
   else if( DH_check( dh, &codes ) != 1 )
   {
      status = -3;
      DH_free( dh );
   }
   /// -# Verify no error codes were encountered
   else if( codes != 0 )
   {
      status = -4;
      DH_free( dh );
   }
   else
   {
      /// -# Allocate BIO memory
      prmBio = BIO_new( BIO_s_mem( ) );

      /// -# Write the DHparams to the BIO
      PEM_write_bio_DHparams( prmBio, dh );

      /// -# Allocate memory and store raw DHparams
      prmLen = BIO_pending( prmBio );
      prmBuf = new unsigned char[ static_cast< unsigned long long >( prmLen ) + 1 ];
      BIO_read( prmBio, prmBuf, prmLen );
      prmBuf[ prmLen ] = '\0';

      /// -# Create new key to return
      *params = new Key( prmBuf, prmLen );

      /// -# Free BIO memory
      BIO_free( prmBio );

      /// -# Free DH memory
      DH_free( dh );
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

static DH* getDH( const Key& params )
{
   DH*  dh = NULL;
   BIO* prmBio = NULL;

   /// @par Process Design Language
   /// -# Create a new Diffie-Hellman instance
   dh = DH_new( );

   if( dh != NULL )
   {
      /// -# Allocate memory for BIO
      prmBio = BIO_new( BIO_s_mem( ) );

      /// -# Write the raw parameters into BIO buffer
      BIO_write( prmBio, params.Buffer( ), params.Length( ) );

      /// -# Read DHparams from BIO into DH structure
      PEM_read_bio_DHparams( prmBio, &dh, NULL, NULL );

      /// -# Free the BIO memory
      BIO_free( prmBio );
   }

   return( dh );
}

