// Application Includes
#include <main.h>
#include <Utility.h>
#include <UnitTest.h>
#include <Simulation.h>

using namespace SecureMigration;

int main( int argc, char** argv )
{
   const unsigned int defKeySize = 1024;

   int       status = 0;
   UnitTest* ut = NULL;
   char*     buffer = NULL;

   if( argc == 1 )
   {
      ut = new UnitTest( defKeySize );
      status = ut->Run( );
   }
   else if( argc == 3 )
   {
      status = Utility::ReadFile( argv[ 2 ], &buffer );

      if( ( argv[ 1 ][ 0 ] == 'D' ) && ( argv[ 1 ][ 1 ] == 'H' ) )
      {
         status = Simulation::RunDiffieHellman( reinterpret_cast< const unsigned char* >( buffer ), status );
      }
      else if( ( argv[ 1 ][ 0 ] == 'R' ) && ( argv[ 1 ][ 1 ] == 'S' ) && ( argv[ 1 ][ 2 ] == 'A' ) )
      {
         status = Simulation::RunRSA( reinterpret_cast< const unsigned char* >( buffer ), status );
      }

      delete[ ] buffer;
   }

   return( status );
}

