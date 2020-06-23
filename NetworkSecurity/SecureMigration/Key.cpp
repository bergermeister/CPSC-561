// Application Includes
#include <Key.h>

// StdLib Includes
#include <string>

using namespace SecureMigration;

Key::Key( unsigned char* buffer, unsigned int length )
{
   this->length = length;
   this->buffer = new unsigned char[ this->length ];
   
   std::memcpy( reinterpret_cast< void* >( this->buffer ), 
                reinterpret_cast< const void* >( buffer ),
                this->length );
}

Key::~Key( void )
{
   delete[ ] this->buffer;
}

Key::Key( const Key& key )
{
   *this = key;
}

Key& Key::operator=( const Key& key )
{
   if( this != &key )
   {
      if( this->buffer != nullptr )
      {
         delete[ ] this->buffer;
      }

      this->length = key.length;
      this->buffer = new unsigned char[ this->length ];
      std::memcpy( reinterpret_cast< void* >( this->buffer ),
                   reinterpret_cast< const void* >( key.buffer ),
                   this->length );
   }

   return( *this );
}

bool Key::operator==( const Key& key ) const
{
   bool equal = false;

   if( this->length == key.length )
   {
      equal = ( std::memcmp( reinterpret_cast< const void* >( this->buffer ),
                             reinterpret_cast< const void* >( key.buffer ),
                             this->length ) == 0 );
   }

   return( equal );
}

const unsigned char* Key::Buffer( void ) const
{
   return( this->buffer );
}

const unsigned int Key::Length( void ) const
{
   return( this->length );
}
