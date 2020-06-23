#pragma once

namespace SecureMigration
{
   namespace Utility
   {
      void PrintHEX( const unsigned char* buffer, int bytes, int bytesPerLine );
      int  ReadFile( const char* fileName, char** buffer );
   }
}

