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
   this->keyPub = nullptr;
   this->keyPri = nullptr;
   this->keySec = nullptr;
}

Session::~Session( void )
{
   this->free( );
}

Session::Session( const Session& session )
{
   *this = session;
}

Session& Session::operator=( const Session& session )
{
   if( this != &session )
   {
      this->free( );

      if( session.params != nullptr )
      {
         this->params = new Key( *session.params );
      }

      if( session.keyPub != nullptr )
      {
         this->keyPub = new Key( *session.keyPub );
      }

      if( session.keyPri != nullptr )
      {
         this->keyPri = new Key( *session.keyPri );
      }

      if( session.keySec != nullptr )
      {
         this->keySec = new Key( *session.keySec );
      }
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
      delete[ ] keyBuf;

      /// -# Extract Private Key
      keyLen = BN_num_bytes( DH_get0_priv_key( dh ) );
      keyBuf = new unsigned char[ static_cast< unsigned long long >( keyLen ) + 1 ];
      keyBuf[ keyLen ] = '\0';
      BN_bn2bin( DH_get0_priv_key( dh ), keyBuf );
      this->keyPri = new Key( keyBuf, keyLen );
      delete[ ] keyBuf;
   }

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
      delete[ ] prmBuf;

      /// -# Free BIO memory
      BIO_free( prmBio );

      /// -# Free DH memory
      DH_free( dh );
   }

   return( status );
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

void Session::free( void )
{
   if( this->params != nullptr )
   {
      delete this->params;
   }

   if( this->keyPub != nullptr )
   {
      delete this->keyPub;
   }

   if( this->keyPri != nullptr )
   {
      delete this->keyPri;
   }

   if( this->keySec != nullptr )
   {
      delete this->keySec;
   }

   this->params = nullptr;
   this->keyPub = nullptr;
   this->keyPri = nullptr;
   this->keySec = nullptr;
}

