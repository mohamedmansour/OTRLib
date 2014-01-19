using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using System.Numerics;
using System.Globalization;



using OTR.Utilities;

namespace OTR.Managers
{
        
    class DHKeysManager
    {
        private UInt32 key_serial = 0;
                
        public DHKeysManager()
        {
           
        }

        public DHKeyPair GenerateKeyPair()
        {
           key_serial++;

           DHKeyPair _key_pair = new DHKeyPair(key_serial);

           _key_pair.SetPrivateKey(Utility.GetRandBigInt(OTRConstants.DH_PRIVATE_KEY_MINIMUM_LENGTH_BITS));
           _key_pair.SetPublicKey(BigInteger.ModPow(OTRConstants.RFC_3526_GENERATOR, _key_pair.GetPrivateKey(), OTRConstants.RFC_3526_PRIME_MODULO()));
           
            return _key_pair;

        }
               
       
   
    
    }


    
}
