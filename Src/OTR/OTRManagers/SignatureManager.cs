using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Windows.Security.Cryptography;
using System.Numerics;
using Org.BouncyCastle.Crypto.Parameters;

using OTR.Utilities;
using System.IO;

namespace OTR.Managers
{
    class SignatureManager
    {
              
      
        byte[] _dsa_public_key_bytes_encoded = null;

        byte[] _encoded_encrypted_signature_byte_array = null;
        byte[] _hashed_encoded_encrypted_byte_array = null;
        byte[] _truncated_hash_signature = null;

       
        DSASigner        _dsa_signer = null;

        

        public SignatureManager(DSASigner dsa_signer)            
        {
            if (dsa_signer == null)
             throw new ArgumentException("SignatureManager: DSA signer object cannot be null");

            _dsa_signer = dsa_signer;
            

            _dsa_public_key_bytes_encoded = new byte[_dsa_signer.GetPublicKeyEncodedMpi().Length];
            Buffer.BlockCopy(_dsa_signer.GetPublicKeyEncodedMpi(), 0, _dsa_public_key_bytes_encoded, 0, _dsa_public_key_bytes_encoded.Length);


                     

            
        }
         
        public void ComputeSignature(AKEKeys ake_keys, byte[] my_public_key_mpi_byte_array, byte[] key_id_byte_array, byte[] their_public_key_mpi_byte_array, UInt64 aes_counter, bool is_top_half_keys)
        {

            

            byte[] hashed_m_byte_array_data = ComputeM(ake_keys, my_public_key_mpi_byte_array, their_public_key_mpi_byte_array, _dsa_public_key_bytes_encoded, key_id_byte_array, is_top_half_keys);
                                   
            byte[] _x_byte_array_data = ComputeX(_dsa_signer, _dsa_public_key_bytes_encoded, key_id_byte_array, hashed_m_byte_array_data);

            
            ComputeSignatureValues(ake_keys, _x_byte_array_data,aes_counter,is_top_half_keys);
        }
        private void ComputeSignatureValues(AKEKeys ake_keys, byte[] x_byte_array_data, UInt64 aes_counter, bool is_top_half_keys)
        {



            if (ake_keys == null)
             throw new ArgumentException("ComputeSignatureValues: AKE keys object should not be null");


            if (is_top_half_keys == true && (ake_keys.GetAESKey1() == null || ake_keys.GetAESKey1().Length < 1))
                throw new ArgumentException("ComputeSignatureValues: The AKE AES key 1 should not be null/empty");

            if (is_top_half_keys == false && (ake_keys.GetAESKey2() == null || ake_keys.GetAESKey2().Length < 1))
                throw new ArgumentException("ComputeSignatureValues: The AKE AES key 2 should not be null/empty");

          

            if (x_byte_array_data == null || x_byte_array_data.Length < 1)
                throw new ArgumentException("ComputeSignatureValues: The x_byte_array_data cannot be null/empty");

            if (aes_counter < 0)
             throw new ArgumentException("ComputeSignatureValues: The aes counter value cannot be less than zero");


            byte[] _encrypted_signature_byte_array = null;

             if (is_top_half_keys == true)           
            _encrypted_signature_byte_array = Utility.AESGetEncrypt(ake_keys.GetAESKey1(), x_byte_array_data, aes_counter);
             else
             _encrypted_signature_byte_array = Utility.AESGetEncrypt(ake_keys.GetAESKey2(), x_byte_array_data, aes_counter);
            

            try
            {

                Utility.EncodeOTRDataBE(_encrypted_signature_byte_array, ref _encoded_encrypted_signature_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("ComputeSignatureValues:" + ex.ToString());

            }





            if (is_top_half_keys == true && (ake_keys.GetMACKey2() == null || ake_keys.GetMACKey2().Length < 1))
             throw new InvalidDataException("ComputeSignatureValues: The AKE MAC key 2 should not be null/empty");


            if (is_top_half_keys == false && (ake_keys.GetMACKey4() == null || ake_keys.GetMACKey4().Length < 1))
                throw new InvalidDataException("ComputeSignatureValues: The AKE MAC key 4 should not be null/empty");



            if (is_top_half_keys == true)            
            _hashed_encoded_encrypted_byte_array = Utility.SHA256GetKeyedHash(ake_keys.GetMACKey2(), _encoded_encrypted_signature_byte_array);
            else
            _hashed_encoded_encrypted_byte_array = Utility.SHA256GetKeyedHash(ake_keys.GetMACKey4(), _encoded_encrypted_signature_byte_array);
           


            _truncated_hash_signature = new byte[OTRConstants.MAC_SIGNATURE_LENGTH_BITS / 8];


            Buffer.BlockCopy(_hashed_encoded_encrypted_byte_array, 0, _truncated_hash_signature, 0, _truncated_hash_signature.Length);




        }

        private static byte[] ComputeM(AKEKeys ake_keys, byte[] my_public_key_mpi_byte_array, byte[] their_public_key_mpi_byte_array, byte[] dsa_public_key_bytes_encoded, byte[] key_id_byte_array, bool is_top_half_keys)
        {

            if (my_public_key_mpi_byte_array == null || my_public_key_mpi_byte_array.Length < 1)
                throw new ArgumentException("ComputeM: My public key mpi byte array cannot be null/empty");


            if (their_public_key_mpi_byte_array == null || their_public_key_mpi_byte_array.Length < 1)
                throw new ArgumentException("ComputeM: Their public key mpi byte array cannot be null/empty");


            if (key_id_byte_array == null || key_id_byte_array.Length < 1)
                throw new ArgumentException("ComputeM: The id byte array cannot be null/empty");

            if (dsa_public_key_bytes_encoded == null || dsa_public_key_bytes_encoded.Length < 1)
                throw new ArgumentException("ComputeM: The encoded DSA public key byte array cannot be null/empty");


            if (ake_keys == null)
              throw new ArgumentException("ComputeM: AKE keys object cannot be null");

            byte[] _encoded_key_id_byte_array = null;

            try
            {
                Utility.EncodeOTRInt(key_id_byte_array, ref _encoded_key_id_byte_array);
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("ComputeM:" + ex.ToString());

            }

            int _m_data_array_length = _encoded_key_id_byte_array.Length + my_public_key_mpi_byte_array.Length +
                 their_public_key_mpi_byte_array.Length +
                 dsa_public_key_bytes_encoded.Length;

            
            byte [] _m_data_array = new byte[_m_data_array_length];


            Buffer.BlockCopy(my_public_key_mpi_byte_array, 0, _m_data_array, 0, my_public_key_mpi_byte_array.Length);
            Buffer.BlockCopy(their_public_key_mpi_byte_array, 0, _m_data_array, my_public_key_mpi_byte_array.Length, their_public_key_mpi_byte_array.Length);

            Buffer.BlockCopy(dsa_public_key_bytes_encoded, 0, _m_data_array, my_public_key_mpi_byte_array.Length + their_public_key_mpi_byte_array.Length, dsa_public_key_bytes_encoded.Length);
            Buffer.BlockCopy(_encoded_key_id_byte_array, 0, _m_data_array, my_public_key_mpi_byte_array.Length + their_public_key_mpi_byte_array.Length + dsa_public_key_bytes_encoded.Length, _encoded_key_id_byte_array.Length);

            if (is_top_half_keys == true && (ake_keys.GetMACKey1() == null || ake_keys.GetMACKey1().Length < 1))
             throw new ArgumentException("ComputeM: The AKE MAC key 1 cannot be null/empty");

            if (is_top_half_keys == false && (ake_keys.GetMACKey3() == null || ake_keys.GetMACKey3().Length < 1))
             throw new ArgumentException("ComputeM: The AKE MAC key 3 cannot be null/empty");

            if (is_top_half_keys == true)
            return Utility.SHA256GetKeyedHash(ake_keys.GetMACKey1(),_m_data_array);
            else
             return Utility.SHA256GetKeyedHash(ake_keys.GetMACKey3(), _m_data_array);
         
            
        }
        private static byte[] ComputeX(DSASigner dsa_signer, byte[] dsa_public_key_bytes_encoded, byte[] key_id_byte_array, byte[] hashed_m_byte_array_data)
        {



            if (key_id_byte_array == null || key_id_byte_array.Length < 1)
                throw new ArgumentException("ComputeX: The key id byte array should not be null/empty");


            if (hashed_m_byte_array_data == null || hashed_m_byte_array_data.Length < 1)
                throw new ArgumentException("ComputeX: The hashed m byte array should not be null/empty");

            if (dsa_signer == null)
                throw new ArgumentException("ComputeX: DSA signer object cannot be null");


            byte[] _signature_r_byte_array = null;
            byte[] _signature_s_byte_array = null;

            dsa_signer.GenerateSignature(hashed_m_byte_array_data, ref _signature_r_byte_array, ref _signature_s_byte_array);

            if (_signature_r_byte_array == null || _signature_r_byte_array.Length < 1)
                throw new InvalidDataException("ComputeX: The computed DSA signature parameter 'r' byte array cannot be null/empty");

            if (_signature_s_byte_array == null || _signature_s_byte_array.Length < 1)
                throw new InvalidDataException("ComputeX: The computed DSA signature parameter 's' byte array cannot be null/empty");



            byte[] _hashed_m_data_signature = null;
            byte[] _encoded_key_id_byte_array = null;



            try
            {
               
                byte[] _encoded_signature_r_byte_array = null;
                byte[] _encoded_signature_s_byte_array = null;

                /* This is unnecessary. It's just here to complement DecodeMacfromBytes used in IsEncryptedSignatureVerified(). 
                 * It should be removed if performance becomes an issue. */
                Utility.EncodeOTRMacBE(_signature_r_byte_array, ref _encoded_signature_r_byte_array);
                Utility.EncodeOTRMacBE(_signature_s_byte_array, ref _encoded_signature_s_byte_array);
               

               
                if (_encoded_signature_r_byte_array == null || _encoded_signature_r_byte_array.Length < 1)
                    throw new InvalidDataException("ComputeX: The encoded DSA signature parameter 'r' byte array cannot be null/empty");

                if (_encoded_signature_s_byte_array == null || _encoded_signature_s_byte_array.Length < 1)
                    throw new InvalidDataException("ComputeX: The encoded DSA signature parameter 's' byte array cannot be null/empty");
                

                _hashed_m_data_signature = new byte[_encoded_signature_r_byte_array.Length + _encoded_signature_s_byte_array.Length];

                Buffer.BlockCopy(_encoded_signature_r_byte_array, 0, _hashed_m_data_signature, 0, _encoded_signature_r_byte_array.Length);
                Buffer.BlockCopy(_encoded_signature_s_byte_array, 0, _hashed_m_data_signature, _encoded_signature_r_byte_array.Length, _encoded_signature_s_byte_array.Length);

                
                Utility.EncodeOTRInt(key_id_byte_array, ref _encoded_key_id_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("ComputeX:" + ex.ToString());

            }



            if (_encoded_key_id_byte_array == null || _encoded_key_id_byte_array.Length < 1)
                throw new InvalidDataException("ComputeX: The encoded key id byte array should not be null/empty");





            int _x_data_array_length = _encoded_key_id_byte_array.Length + dsa_public_key_bytes_encoded.Length + _hashed_m_data_signature.Length;


            byte[] _x_data_array = new byte[_x_data_array_length];

            Buffer.BlockCopy(dsa_public_key_bytes_encoded, 0, _x_data_array, 0, dsa_public_key_bytes_encoded.Length);
            Buffer.BlockCopy(_encoded_key_id_byte_array, 0, _x_data_array, dsa_public_key_bytes_encoded.Length, _encoded_key_id_byte_array.Length);
            Buffer.BlockCopy(_hashed_m_data_signature, 0, _x_data_array, dsa_public_key_bytes_encoded.Length + _encoded_key_id_byte_array.Length, _hashed_m_data_signature.Length);





            return _x_data_array;
        }

        
        private byte [] GetEncodedEncryptedSignatureBytes()
        {

            if (_encoded_encrypted_signature_byte_array == null || _encoded_encrypted_signature_byte_array.Length < 1)
               throw new InvalidDataException("GetHashedSignatureBytes: Encoded encrypted signature value is invalid. Make sure ComputeAuthValues function has been called");


            return _encoded_encrypted_signature_byte_array;

        }
        private byte [] GetHashedSignatureBytes()
        {
            if (_truncated_hash_signature == null || _truncated_hash_signature.Length < 1)
            throw new InvalidDataException("GetHashedSignatureBytes: Truncated hashed signature value is invalid. Make sure ComputeAuthValues function has been called");

                                      
            return _truncated_hash_signature;

        }

        public byte[] GetSignatureDataBytes()
        {


            if (_truncated_hash_signature == null || _truncated_hash_signature.Length < 1)
                throw new InvalidDataException("GetSignatureDataBytes: Truncated hashed signature value is invalid. Make sure ComputeAuthValues function has been called");

            if (_encoded_encrypted_signature_byte_array == null || _encoded_encrypted_signature_byte_array.Length < 1)
              throw new InvalidDataException("GetSignatureDataBytes: Encoded encrypted signature value is invalid. Make sure ComputeAuthValues function has been called");


           byte[] _signature_data = new byte[_encoded_encrypted_signature_byte_array.Length + _truncated_hash_signature.Length];

           Buffer.BlockCopy(_encoded_encrypted_signature_byte_array, 0, _signature_data, 0, _encoded_encrypted_signature_byte_array.Length);

           
            Buffer.BlockCopy(_truncated_hash_signature, 0, _signature_data, _encoded_encrypted_signature_byte_array.Length, _truncated_hash_signature.Length);

                    
            return _signature_data;

        }

        public int GetSignatureDataLength()
        {
            if (_truncated_hash_signature == null || _truncated_hash_signature.Length < 1)
                throw new InvalidDataException("GetSignatureDataLength: Truncated hashed signature value is invalid. Make sure ComputeAuthValues function has been called");

            if (_encoded_encrypted_signature_byte_array == null || _encoded_encrypted_signature_byte_array.Length < 1)
               throw new InvalidDataException("GetSignatureDataLength: Encoded encrypted signature value is invalid. Make sure ComputeAuthValues function has been called");

            return _encoded_encrypted_signature_byte_array.Length + _truncated_hash_signature.Length;

        }
        

        public static bool IsSignatureVerified(AKEKeys ake_keys, DHKeyPair key_pair, byte[] their_public_key_mpi_byte_array, byte[] encrypted_signature_byte_array,
            byte[] hashed_encrypted_signature_byte_array, bool is_top_half_keys, ref UInt32 public_key_id, ref byte[] dsa_public_key_byte_array_encoded)
        {

          
            if (encrypted_signature_byte_array == null || encrypted_signature_byte_array.Length < 1)
                throw new ArgumentException("IsSignatureVerified: Encrypted signature byte array cannot be null/empty");


            if (hashed_encrypted_signature_byte_array == null || hashed_encrypted_signature_byte_array.Length < 1)
             throw new ArgumentException("IsSignatureVerified: The hashed encrypted byte array cannot be null/empty");


            if (ake_keys == null)
             throw new ArgumentException("IsSignatureVerified: The AKE keys cannot be null");

            bool _is_hash_verified = false;


            if (is_top_half_keys == true)
                _is_hash_verified = IsHashSignatureVerified(ake_keys.GetMACKey2(), encrypted_signature_byte_array, hashed_encrypted_signature_byte_array);
            else
                _is_hash_verified = IsHashSignatureVerified(ake_keys.GetMACKey4(), encrypted_signature_byte_array, hashed_encrypted_signature_byte_array);
           
            
            
            if (_is_hash_verified == false)
             return false;


           
             if (IsEncryptedSignatureVerified(ake_keys, key_pair, their_public_key_mpi_byte_array,
                 encrypted_signature_byte_array, 0, is_top_half_keys, ref public_key_id, ref dsa_public_key_byte_array_encoded) == false)
              return false;

         

           return true;
        }

        private static bool IsHashSignatureVerified(byte [] hash_key_byte_array,byte [] byte_array_to_hash, byte [] hashed_byte_array)
        {

            if (hash_key_byte_array == null || hash_key_byte_array.Length < 1)
                throw new ArgumentException("IsHashSignatureVerified: The hash key byte array cannot be null/empty");


           
            byte[] _hash_byte_array = Utility.SHA256GetKeyedHash(hash_key_byte_array, byte_array_to_hash);

            //truncate the 256 bits to 160 bits

            byte[] _hash_byte_array_truncated = new byte[OTRConstants.MAC_SIGNATURE_LENGTH_BITS / 8];
            
            Buffer.BlockCopy(_hash_byte_array, 0, _hash_byte_array_truncated, 0, _hash_byte_array_truncated.Length);

           


            return Utility.IsArrayEqual(_hash_byte_array_truncated, hashed_byte_array);
           



           


        }
        

        private static bool IsEncryptedSignatureVerified(AKEKeys ake_keys, DHKeyPair key_pair, byte[] their_public_key_mpi_byte_array,
            byte[] encryted_byte_array, UInt64 counter, bool is_top_half_keys,ref UInt32 public_key_id, ref byte[] dsa_public_key_byte_array_encoded)
        {

            


            int _next_start_index = -1;
            bool _is_verified = false;
            byte[] _decrypted_x_data_array = null;
            byte[] _hashed_m_data_signature = null;
            byte[] _dh_kid_bytes = null;
            byte[] _temp_byte_array = null;
            byte[] _dsa_public_key_type = null;

            byte[] _dsa_public_key_param_p_mpi = null;
            byte[] _dsa_public_key_param_q_mpi = null;
            byte[] _dsa_public_key_param_g_mpi = null;
            byte[] _dsa_public_key_param_y_mpi = null;

           

            try
            {

                /*get encrypted signature bytes*/


                _next_start_index = 0;
                _temp_byte_array = null;
                _next_start_index = Utility.DecodeDataFromBytesBE(encryted_byte_array, _next_start_index, ref _temp_byte_array);

                if (_temp_byte_array == null || _temp_byte_array.Length < 1)
                    throw new InvalidDataException("IsEncryptedSignatureVerified: The decoded Encrypted OTR Data type byte array cannot be null/empty");

                if (is_top_half_keys == true)
                _decrypted_x_data_array = Utility.AESGetDecrypt(ake_keys.GetAESKey1(), _temp_byte_array, counter);
                else
                _decrypted_x_data_array = Utility.AESGetDecrypt(ake_keys.GetAESKey2(), _temp_byte_array, counter);




                if (_decrypted_x_data_array == null || _decrypted_x_data_array.Length < 1)
                    throw new InvalidDataException("IsEncryptedSignatureVerified: The decrypted byte array cannot be null/empty");


                /*get public key parameter bytes*/

                _next_start_index = 0;
                _temp_byte_array = null;

               

                //get public key type
                int _pub_key_start_index = _next_start_index;
                _next_start_index = Utility.DecodeShortFromBytes(_decrypted_x_data_array, _next_start_index, ref  _dsa_public_key_type);

                if (_dsa_public_key_type == null || _dsa_public_key_type.Length < 1)
                    throw new InvalidDataException("IsEncryptedSignatureVerified: The decoded DSA public key type byte array cannot be null/empty");

                
                if (BitConverter.ToUInt16(_dsa_public_key_type,0) != OTRConstants.DSA_PUB_KEY_TYPE)
                throw new InvalidDataException("IsEncryptedSignatureVerified: The DSA public key type is invalid");

                
                
                //get MPI encoded DSA public key parameters
                _next_start_index = Utility.DecoupleMpiFromBytes(_decrypted_x_data_array, _next_start_index, ref _dsa_public_key_param_p_mpi);
                _next_start_index = Utility.DecoupleMpiFromBytes(_decrypted_x_data_array, _next_start_index, ref _dsa_public_key_param_q_mpi);
                _next_start_index = Utility.DecoupleMpiFromBytes(_decrypted_x_data_array, _next_start_index, ref _dsa_public_key_param_g_mpi);
                _next_start_index = Utility.DecoupleMpiFromBytes(_decrypted_x_data_array, _next_start_index, ref _dsa_public_key_param_y_mpi);

                int _pub_key_end_index = _next_start_index;

                //get the whole encoded DSA key

                dsa_public_key_byte_array_encoded = new byte[_pub_key_end_index - _pub_key_start_index];
                Buffer.BlockCopy(_decrypted_x_data_array, _pub_key_start_index, dsa_public_key_byte_array_encoded, 0, dsa_public_key_byte_array_encoded.Length);
          

                DsaPublicKeyParameters _dsa_public_key_params = GetDSAPublicKeyParams(_dsa_public_key_param_p_mpi, _dsa_public_key_param_q_mpi, _dsa_public_key_param_g_mpi, _dsa_public_key_param_y_mpi);


                /*Get DH Key ID bytes*/

                _next_start_index = Utility.DecodeIntFromBytes(_decrypted_x_data_array, _next_start_index, ref _dh_kid_bytes);

              
                if (_dh_kid_bytes == null || _dh_kid_bytes.Length < 1)
                throw new InvalidDataException("IsEncryptedSignatureVerified: The decoded Key ID OTR Int type byte array cannot be null/empty");

                                
                public_key_id = BitConverter.ToUInt32(_dh_kid_bytes, 0);


                /*Get Signed M_b*/

                _hashed_m_data_signature = new byte[_decrypted_x_data_array.Length - _next_start_index];
                Buffer.BlockCopy(_decrypted_x_data_array, _next_start_index, _hashed_m_data_signature, 0, _hashed_m_data_signature.Length);

                if (_hashed_m_data_signature == null || _hashed_m_data_signature.Length < 1)
                throw new InvalidDataException("IsEncryptedSignatureVerified: The extracted Signed byte array, M_b, cannot be null/empty");


                /*Decode r and s  */

                                
                _next_start_index = 0;                               

               
                byte[] _decoded_signature_r_byte_array = null;
                byte[] _decoded_signature_s_byte_array = null;


                _next_start_index = Utility.DecodeMacFromBytesBE(_hashed_m_data_signature, _next_start_index, ref _decoded_signature_r_byte_array);
                _next_start_index = Utility.DecodeMacFromBytesBE(_hashed_m_data_signature, _next_start_index, ref _decoded_signature_s_byte_array);


               
                if (_decoded_signature_r_byte_array == null || _decoded_signature_r_byte_array.Length < 1)
                    throw new InvalidDataException("IsEncryptedSignatureVerified: The decoded DSA signature parameter 'r' byte array cannot be null/empty");

                if (_decoded_signature_s_byte_array == null || _decoded_signature_s_byte_array.Length < 1)
                  throw new InvalidDataException("IsEncryptedSignatureVerified: The decoded DSA signature parameter 's' byte array cannot be null/empty");





                /*Verify Signature*/


                byte[] _hashed_m_data_byte_array = ComputeM(ake_keys, their_public_key_mpi_byte_array, key_pair.GetPublicKeyMpiBytes(), dsa_public_key_byte_array_encoded, _dh_kid_bytes, is_top_half_keys);

                _is_verified = DSASigner.VerifySignature(_dsa_public_key_params, _hashed_m_data_byte_array, _decoded_signature_r_byte_array, _decoded_signature_s_byte_array);

               



            }
            catch (Exception ex)
            {
                _is_verified = false;
                throw new InvalidDataException("IsEncryptedVerified:" + ex.ToString());

            }




            return _is_verified;







        }

        private static DsaPublicKeyParameters GetDSAPublicKeyParams(byte[] dsa_p_mpi, byte[] dsa_q_mpi, byte[] dsa_g_mpi, byte[] dsa_y_mpi)
        {



            if (dsa_p_mpi == null || dsa_p_mpi.Length < 1)
                throw new ArgumentException("GetDSAPublicKeyParams: DSA P Key parameter mpi byte array cannot be null/empty");


            if (dsa_q_mpi == null || dsa_q_mpi.Length < 1)
                throw new ArgumentException("GetDSAPublicKeyParams: DSA Q Key parameter mpi byte array cannot be null/empty");



            if (dsa_g_mpi == null || dsa_g_mpi.Length < 1)
                throw new ArgumentException("GetDSAPublicKeyParams: DSA G Key parameter mpi byte array cannot be null/empty");


            if (dsa_y_mpi == null || dsa_y_mpi.Length < 1)
                throw new ArgumentException("GetDSAPublicKeyParams: DSA Y Key parameter mpi byte array cannot be null/empty");

           

            Org.BouncyCastle.Math.BigInteger _P = null;
            Org.BouncyCastle.Math.BigInteger _Q = null;
            Org.BouncyCastle.Math.BigInteger _G = null;
            Org.BouncyCastle.Math.BigInteger _Y = null;

            Utility.DecodeMpiFromBytes(dsa_p_mpi, 0, ref _P);
            Utility.DecodeMpiFromBytes(dsa_q_mpi, 0, ref _Q);
            Utility.DecodeMpiFromBytes(dsa_g_mpi, 0, ref _G);
            Utility.DecodeMpiFromBytes(dsa_y_mpi, 0, ref _Y);
            
            
          DsaParameters _dsa_param         = new DsaParameters(_P, _Q, _G);
          DsaKeyParameters _dsa_key_params = new DsaKeyParameters(false, _dsa_param);
          DsaPublicKeyParameters _public_key_param = new DsaPublicKeyParameters(_Y, _dsa_param);


          return _public_key_param;
        }
        
       
    }
}
