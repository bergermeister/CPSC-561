// Application Includes
#include <Utility.h>

// StdLib Includes
#include <iostream>
#include <fstream>

using namespace SecureMigration;

void Utility::PrintHEX( const unsigned char* buffer, int bytes, int bytesPerLine )
{
   const char map[ ] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
   int offset;
   int limit = bytesPerLine - 1;

   for( offset = 0; offset < bytes; offset++ )
   {
      std::cout << map[ ( buffer[ offset ] >> 4 ) & 0x0F ] << map[ buffer[ offset ] & 0x04 ];
      if( ( offset % bytesPerLine ) == limit )
      {
         std::cout << std::endl;
      }
   }

   if( ( offset % bytesPerLine ) == 0 )
   {
      std::cout << std::endl;
   }
}

int Utility::ReadFile( const char* fileName, char** buffer )
{
   int status;
   std::ifstream in;

   in.open( fileName, std::ios::in | std::ios::ate );
   if( !in.is_open( ) )
   {
      status = -1;
   }
   else
   {
      status = in.tellg( );
      *buffer = new char[ status ];

      in.close( );
      in.open( fileName, std::ios::in );
      in.read( *buffer, status );
      in.close( );
   }

   return( status );
}

