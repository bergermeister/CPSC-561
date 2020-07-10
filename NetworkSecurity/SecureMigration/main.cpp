// Application Includes
#include <main.h>
#include <Utility.h>
#include <UnitTest.h>
#include <Simulation.h>

// StdLib Includes
#include <string>

using namespace SecureMigration;

int main( int argc, char** argv )
{
   const unsigned int defKeySize = 1024;

   int       status = 0;
   int       dataLen = 0;
   int       keyLen = 1024;
   UnitTest* ut = NULL;
   char*     buffer = NULL;

   if( argc == 1 )
   {
      ut = new UnitTest( defKeySize );
      status = ut->Run( );
   }
   else if( argc == 4 )
   {
      keyLen = std::stoi( argv[ 2 ] );
      dataLen = Utility::ReadFile( argv[ 3 ], &buffer );

      if( ( argv[ 1 ][ 0 ] == 'D' ) && ( argv[ 1 ][ 1 ] == 'H' ) )
      {
         status = Simulation::RunDiffieHellman( reinterpret_cast< const unsigned char* >( buffer ), dataLen, keyLen );
      }
      else if( ( argv[ 1 ][ 0 ] == 'R' ) && ( argv[ 1 ][ 1 ] == 'S' ) && ( argv[ 1 ][ 2 ] == 'A' ) )
      {
         status = Simulation::RunRSA( reinterpret_cast< const unsigned char* >( buffer ), dataLen, keyLen );
      }
      else
      {
         status = Simulation::RunDiffieHellman( reinterpret_cast< const unsigned char* >( buffer ), dataLen, keyLen );
         status |= Simulation::RunRSA( reinterpret_cast< const unsigned char* >( buffer ), dataLen, keyLen );
      }

      delete[ ] buffer;
   }

   return( status );
}

