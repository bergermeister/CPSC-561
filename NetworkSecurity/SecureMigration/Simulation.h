#pragma once

namespace SecureMigration
{
   namespace Simulation
   {
      int RunDiffieHellman( const unsigned char* plaintext, const int size, const int keyLen );
      int RunRSA( const unsigned char* plaintext, const int size, const int keyLen );
   }
}

