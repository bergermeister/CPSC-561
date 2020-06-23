#pragma once

namespace SecureMigration
{
   namespace Simulation
   {
      int RunDiffieHellman( const unsigned char* plaintext, int size );
      int RunRSA( const unsigned char* plaintext, int size );
   }
}

