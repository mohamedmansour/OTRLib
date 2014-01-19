using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using System.Numerics;


using OTR.Utilities;

namespace OTR.Managers
{

   // Authenticated Key Exchange (AKE)
    class AKEKeysManager
    {

        private AKEKeys _ake_keys = null;
        private BigInteger _secret = 0;
        private byte[] _sec_data_byte_array_mpi = null;
        
        
        public AKEKeys ComputeKeys(DHKeyPair my_key_pair, BigInteger public_key)
        {

            if (Utility.IsValidPublicKey(public_key) == false)
            throw new ArgumentException("AKEKeysManager:Public key is invalid");


            if (my_key_pair == null)
                throw new ArgumentException("AKEKeysManager:  My Key Pair cannot be null");

            if (my_key_pair.GetPrivateKey() < 1)
                throw new ArgumentException("AKEKeysManager: Private key in my_key_pair value cannot be less than 0");

            if (public_key < 1)
                throw new ArgumentException("AKEKeysManager: Public key value cannot be less than 0");

            
            
               _ake_keys = new AKEKeys();


               _secret = Utility.ComputeSecret(my_key_pair, public_key, OTRConstants.RFC_3526_GENERATOR, OTRConstants.RFC_3526_PRIME_MODULO());

               Utility.SetSecByteMpi(_secret, ref  _sec_data_byte_array_mpi);

               _ake_keys.SetSecData(_sec_data_byte_array_mpi);

               ComputeSessionIDByte();
               ComputeEncryptionKeysBytes();
               ComputeMACKeysBytes();



               return _ake_keys;



        }
                   
        private void ComputeSessionIDByte()
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
            throw new ArgumentException("ComputeSessionIDByte: Sec data bytes cannot be null/empty");

            _sec_data_byte_array_mpi[0] = OTRConstants.SESS_ID_FIRST_BYTE_VALUE;



            byte[] _sha_256_bytes = Utility.SHA256GetHash(_sec_data_byte_array_mpi);
            byte[] _session_id = new byte[8];
            
            Buffer.BlockCopy(_sha_256_bytes, 0, _session_id, 0, _session_id.Length);


            if (_ake_keys == null)
            throw new ArgumentException("ComputeSessionIDByte: AESKeys object cannot be null");

            
            _ake_keys.SetSessionID(_session_id);

           

           
           

          
        }                
        private void ComputeEncryptionKeysBytes()
        {


            if (_ake_keys == null)
                throw new ArgumentException("ComputeEncryptionKeysBytes: AESKeys object cannot be null");

            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeEncryptionKeysBytes: SecBytes Plus 5 cannot be null/empty");


            byte[] encryption_key_1 = new byte[OTRConstants.AES_KEY_LENGTH_BITS / 8];
            byte[] encryption_key_2 = new byte[OTRConstants.AES_KEY_LENGTH_BITS / 8];




            _sec_data_byte_array_mpi[0] = OTRConstants.AES_KEYS_FIRST_BYTE_VALUE;


            byte[] _sha_256_bytes = Utility.SHA256GetHash(_sec_data_byte_array_mpi);

            Buffer.BlockCopy(_sha_256_bytes, 0, encryption_key_1, 0, encryption_key_1.Length);
            Buffer.BlockCopy(_sha_256_bytes, 16, encryption_key_2, 0, encryption_key_2.Length);




           

            _ake_keys.SetAESKey1(encryption_key_1);
            _ake_keys.SetAESKey2(encryption_key_2);


           
                


        }        
        private void ComputeMACKeysBytes()
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeMACKeysBytes: Sec data array cannot be null/empty");

            if (_ake_keys == null)
             throw new ArgumentException("ComputeMACKeysBytes: AESKeys object cannot be null");



            byte[] _mac_key = new byte[OTRConstants.MAC_KEY_LENGTH_BITS / 8];


            Buffer.BlockCopy(ComputeMacBytes(OTRConstants.MAC_KEY_1_FIRST_BYTE_VALUE), 0, _mac_key, 0, _mac_key.Length);    
            _ake_keys.SetMACKey1(_mac_key);

           

            Buffer.BlockCopy(ComputeMacBytes(OTRConstants.MAC_KEY_2_FIRST_BYTE_VALUE), 0, _mac_key, 0, _mac_key.Length);
            _ake_keys.SetMACKey2(_mac_key);

           

            Buffer.BlockCopy(ComputeMacBytes(OTRConstants.MAC_KEY_3_FIRST_BYTE_VALUE), 0, _mac_key, 0, _mac_key.Length);
            _ake_keys.SetMACKey3(_mac_key);

           


            Buffer.BlockCopy(ComputeMacBytes(OTRConstants.MAC_KEY_4_FIRST_BYTE_VALUE), 0, _mac_key, 0, _mac_key.Length);
            _ake_keys.SetMACKey4(_mac_key);



           


        }
        private byte[] ComputeMacBytes(byte first_byte_value)
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeMacBytes: Sec data array cannot be null/empty");

            _sec_data_byte_array_mpi[0] = first_byte_value;



            return Utility.SHA256GetHash(_sec_data_byte_array_mpi);
        }

        

    }

  
   
}
