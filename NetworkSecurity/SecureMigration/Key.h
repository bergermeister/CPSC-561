#pragma once

namespace SecureMigration
{
   class Key
   {
   private:    // Private Attributes
      unsigned char* buffer;
      unsigned int   length;

   public:     // Public Methods
      Key( unsigned char* buffer, unsigned int length );
      ~Key( void );

      Key( const Key& key );
      Key& operator=( const Key& key );
      bool operator==( const Key& key ) const;

      const unsigned char* Buffer( void ) const;
      const unsigned int   Length( void ) const;
   };
}

