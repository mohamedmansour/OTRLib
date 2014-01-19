using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Numerics;


using OTR.Utilities;

namespace OTR.Managers
{
    class DataExchangeKeysManager
    {

        private OTR_END_TYPE _end_type = OTR_END_TYPE.INVALID;
        private DataExchangeKeys _data_exchange_keys = null;
        private BigInteger _secret = 0; 

        private byte _send_byte = 0;
        private byte _recv_byte = 0;
        byte[]  _sec_data_byte_array_mpi = null;
       


        public DataExchangeKeys ComputeKeys(DHKeyPair my_key_pair, BigInteger buddy_public_key)
        {
            
            if (Utility.IsValidPublicKey(buddy_public_key) == false)
                throw new ArgumentException("DataExchangeKeysManager:Buddy public key is invalid");


            if (my_key_pair == null)
                throw new ArgumentException("DataExchangeKeysManager:  My Key Pair cannot be null");

            if (my_key_pair.GetPrivateKey() < 1)
                throw new ArgumentException("DataExchangeKeysManager: Private key in my_key_pair value cannot be less than 0");

            if (buddy_public_key < 1)
            throw new ArgumentException("DataExchangeKeysManager: Buddy public key value cannot be less than 0");



            if (my_key_pair.GetPublicKey() > buddy_public_key)
            {
                _end_type =  OTR_END_TYPE.HIGH_END;
                _send_byte = OTRConstants.HIGH_END_SEND_BYTE_VALUE;
                _recv_byte = OTRConstants.HIGH_END_RECV_BYTE_VALUE;
            }
            else
            {
                _end_type =   OTR_END_TYPE.LOW_END;
                _send_byte = OTRConstants.LOW_END_SEND_BYTE_VALUE;
                _recv_byte = OTRConstants.LOW_END_RECV_BYTE_VALUE;
            }



            _data_exchange_keys = new DataExchangeKeys();
            _data_exchange_keys.SetEndType(_end_type);


            _secret = Utility.ComputeSecret(my_key_pair, buddy_public_key, OTRConstants.RFC_3526_GENERATOR, OTRConstants.RFC_3526_PRIME_MODULO());

            Utility.SetSecByteMpi(_secret, ref  _sec_data_byte_array_mpi);


            _data_exchange_keys.SetSecData(_sec_data_byte_array_mpi);


            ComputeSendKeys();
            ComputeRecvKeys();
            ComputeAesExtraKey();

            return _data_exchange_keys;
        }
        
        private void ComputeSendKeys()
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeSendKeys: Sec data array cannot be null/empty");


            if (_data_exchange_keys == null)
             throw new ArgumentException("ComputeSendKeys: DataExchnageKeys object cannot be null");

            _sec_data_byte_array_mpi[0] = _send_byte;



            byte[] _sha_1_bytes = Utility.SHA1GetHash(_sec_data_byte_array_mpi);
            byte[] _aes_send_key = new byte[OTRConstants.AES_SEND_KEY_LENGTH_BITS / 8];
            
            Buffer.BlockCopy(_sha_1_bytes, 0, _aes_send_key, 0, _aes_send_key.Length);


            _sha_1_bytes = Utility.SHA1GetHash(_aes_send_key);
            byte[] _mac_send_key = new byte[OTRConstants.MAC_SEND_KEY_LENGTH_BITS / 8];


            Buffer.BlockCopy(_sha_1_bytes, 0, _mac_send_key, 0, _mac_send_key.Length);
            

            _data_exchange_keys.SetAESKeySend(_aes_send_key);
            _data_exchange_keys.SetMACKeySend(_mac_send_key);


        }

        private void ComputeRecvKeys()
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeRecvKeys: Sec data array cannot be null/empty");


            if (_data_exchange_keys == null)
             throw new ArgumentException("ComputeRecvKeys: DataExchnageKeys object cannot be null");


            _sec_data_byte_array_mpi[0] = _recv_byte;


            byte[] _sha_1_bytes = Utility.SHA1GetHash(_sec_data_byte_array_mpi);
            byte[] _aes_recv_key = new byte[OTRConstants.AES_RECV_KEY_LENGTH_BITS / 8];

            Buffer.BlockCopy(_sha_1_bytes, 0, _aes_recv_key, 0, _aes_recv_key.Length);


            _sha_1_bytes = Utility.SHA1GetHash(_aes_recv_key);
            byte[] _mac_recv_key = new byte[OTRConstants.MAC_RECV_KEY_LENGTH_BITS / 8];


            Buffer.BlockCopy(_sha_1_bytes, 0, _mac_recv_key, 0, _mac_recv_key.Length);



            _data_exchange_keys.SetAESKeyRecv(_aes_recv_key);
            _data_exchange_keys.SetMACKeyRecv(_mac_recv_key);





        }

        private void ComputeAesExtraKey()
        {
            if (_sec_data_byte_array_mpi == null || _sec_data_byte_array_mpi.Length == 0)
                throw new ArgumentException("ComputeAesExtraKey: Sec data array cannot be null/empty");


            if (_data_exchange_keys == null)
            throw new ArgumentException("ComputeAesExtraKey: DataExchnageKeys object cannot be null");


            _sec_data_byte_array_mpi[0] = OTRConstants.AES_EXTRA_KEY_FIRST_BYTE_VALUE;


            byte[] _aes_key_extra = Utility.SHA256GetHash(_sec_data_byte_array_mpi);


           _data_exchange_keys.SetAESKeyExtra(_aes_key_extra);


        }

               
        
        
        public byte[] GetSecDataMpi()
        {
            return _sec_data_byte_array_mpi;

        }
    }
}
