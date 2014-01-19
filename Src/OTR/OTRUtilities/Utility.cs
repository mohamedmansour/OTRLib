using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;


using System.Numerics;
using System.Globalization;
using Windows.Security.Cryptography;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Generators;
using Windows.Security.Cryptography.Core;




namespace OTR.Utilities
{
    class Utility
    {

        static Random _random_gen;

        #region  Encrypt and Hash functions

        public static byte[] SHA256GetHash(byte[] byte_array)
        {
           
            if (byte_array == null || byte_array.Length == 0)
            throw new ArgumentException("GetSHA256: Data to be hashed be null/empty");


            HashAlgorithmProvider provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);

            var ibuff = CryptographicBuffer.CreateFromByteArray(byte_array);
            var hashbuff = provider.HashData(ibuff);

            var hashByteArr = new byte[hashbuff.Length];
            CryptographicBuffer.CopyToByteArray(hashbuff, out hashByteArr);
            return hashByteArr;
        }
        public static byte[] SHA256GetKeyedHash(byte[] key, byte[] data_byte_array)
        {
             //http://tools.ietf.org/html/rfc2104
            // http://msdn.microsoft.com/en-us/library/system.security.cryptography.hmacsha256.aspx

            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);

            var keyMaterial = CryptographicBuffer.CreateFromByteArray(key);
            var cryptoKey = provider.CreateKey(keyMaterial);

            var data = CryptographicBuffer.CreateFromByteArray(data_byte_array);
            var signedBuff = CryptographicEngine.Sign(cryptoKey, data);

            var hashByteArr = new byte[signedBuff.Length];
            CryptographicBuffer.CopyToByteArray(signedBuff, out hashByteArr);
            return hashByteArr;

        }
       
        
        public static byte[] SHA1GetHash(byte[] byte_array)
        {
            if (byte_array == null || byte_array.Length == 0)
                throw new ArgumentException("GetSHA1: Data to be hashed be null/empty");

            /* No need to reverse as all data are already encoded*/

            HashAlgorithmProvider provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha1);

            var ibuff = CryptographicBuffer.CreateFromByteArray(byte_array);
            var hashbuff = provider.HashData(ibuff);

            var hashByteArr = new byte[hashbuff.Length];
            CryptographicBuffer.CopyToByteArray(hashbuff, out hashByteArr);
            return hashByteArr;
        }
        public static byte[] SHA1GetKeyedHash(byte[] key, byte[] data_byte_array)
        {
            /* No need to reverse as all data are already encoded including the keys */
            /* Most of the keys are derived for sec_data_encoded_mpi */

            MacAlgorithmProvider provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);

            var keyMaterial = CryptographicBuffer.CreateFromByteArray(key);
            var cryptoKey = provider.CreateKey(keyMaterial);

            var data = CryptographicBuffer.CreateFromByteArray(data_byte_array);
            var signedBuff = CryptographicEngine.Sign(cryptoKey, data);

            var hashByteArr = new byte[signedBuff.Length];
            CryptographicBuffer.CopyToByteArray(signedBuff, out hashByteArr);
            return hashByteArr;
        }
        
        public static byte[] AESGetEncrypt(byte[] key, byte[] plain_data_array, UInt64 counter)
        {

            if (key == null || key.Length == 0 || key.Length != 16)
                throw new ArgumentException("AESGetEncrypt: The key cannot be null/empty and must be 16 bytes in length");

            if (plain_data_array == null || plain_data_array.Length == 0)
                throw new ArgumentException("AESGetEncrypt: The plain data be null/empty");



            var _cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            ParametersWithIV _parameter_with_iv = new ParametersWithIV(new KeyParameter(key), GetAESCounterBytes(counter));
            _cipher.Init(true, _parameter_with_iv);



            return _cipher.DoFinal(plain_data_array);



        }
        public static byte[] AESGetDecrypt(byte[] key, byte[] encrypted_data_array, UInt64 counter)
        {

            if (key == null || key.Length == 0 || key.Length != 16)
                throw new ArgumentException("AESGetDecrypt: The key cannot be null/empty and must be 16 bytes in length");

            if (encrypted_data_array == null || encrypted_data_array.Length == 0)
                throw new ArgumentException("AESGetDecrypt: The encrypted data be null/empty");


            var _cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            ParametersWithIV _parameter_with_iv = new ParametersWithIV(new KeyParameter(key), GetAESCounterBytes(counter));
            _cipher.Init(false, _parameter_with_iv);



            return _cipher.DoFinal(encrypted_data_array);

        }
        public static byte[] AESGetDecrypt(byte[] key, byte[] encrypted_data_array, byte [] counter)
        {

            if (key == null || key.Length == 0 || key.Length != 16)
                throw new ArgumentException("AESGetDecrypt: The key cannot be null/empty and must be 16 bytes in length");

            if (encrypted_data_array == null || encrypted_data_array.Length == 0)
                throw new ArgumentException("AESGetDecrypt: The encrypted data be null/empty");


            var _cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            ParametersWithIV _parameter_with_iv = new ParametersWithIV(new KeyParameter(key), GetAESCounterBytes(counter));
            _cipher.Init(false, _parameter_with_iv);



            return _cipher.DoFinal(encrypted_data_array);

        }


        private static byte[] GetAESCounterBytes(UInt64 counter)
        {
            byte[] _counter_bytes_8 = BitConverter.GetBytes(counter);


            if (BitConverter.IsLittleEndian == true)
                Array.Reverse(_counter_bytes_8);


            return GetAESCounterBytes(_counter_bytes_8);

        }
        private static byte[] GetAESCounterBytes(byte[] counter_bytes)
        {
            //expects big endian byte array

            if (counter_bytes == null || counter_bytes.Length < 8)
                throw new ArgumentException("The counter bytes cannot be null or its length less than 8");

            byte[] _counter_byte_16 = new byte[16];

            for (int i = 0; i < counter_bytes.Length; i++)
            {
                _counter_byte_16[i] = counter_bytes[i];
            }



            return _counter_byte_16;
        }
        


        #endregion

        #region  Random generation functions

        public static byte[] GetRandomByteArray(int byte_array_length)
        {
            byte[] _random_byte_array = new byte[byte_array_length];
            var ibuffer = CryptographicBuffer.GenerateRandom((uint)byte_array_length);
            CryptographicBuffer.CopyToByteArray(ibuffer, out _random_byte_array);
            return _random_byte_array;
        }
        public static UInt32 GetRandomInteger(int min_value)
        {

            
            if (_random_gen == null)
            _random_gen = new Random();

          int _random_int = _random_gen.Next(min_value, int.MaxValue);

          if (_random_int < 0)
            _random_int *=- 1;
            
          return (UInt32)_random_int;

            
        }
        public static BigInteger GetRandBigInt(int private_key_length_bits)
        {


            if (private_key_length_bits < OTRConstants.DH_PRIVATE_KEY_MINIMUM_LENGTH_BITS)
                throw new ArgumentException("GetRandBigInt: Key length cannot be less than " + OTRConstants.DH_PRIVATE_KEY_MINIMUM_LENGTH_BITS.ToString());

            byte[] _random_bytes = GetRandomByteArray(private_key_length_bits / 8);
            BigInteger _big_int_val = new BigInteger(_random_bytes);

            if (_big_int_val.Sign == -1)
            {
                byte[] _norm = NormalizeBigInt(_big_int_val.ToByteArray());
                _big_int_val = new BigInteger(_norm);

            }

           
            return _big_int_val;

        }

      
        
        
        #endregion

       
        #region  OTR Encoding functions

        private static void EncodeOTRBytes(byte[] in_byte_array, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {
            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeOTRBytes: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
            throw new ArgumentException("EncodeOTRBytes: The OTR data len type is invalid");

           
            int _type_length = GetOTRDataLenType(otr_data_len_type);

             if (in_byte_array.Length > _type_length)
            throw new ArgumentException("EncodeOTRBytes: In byte length cannot greater than " + _type_length.ToString());



            out_byte_array = new byte[_type_length];

            Buffer.BlockCopy(in_byte_array, 0, out_byte_array, 0, out_byte_array.Length);
           
                if (BitConverter.IsLittleEndian == true)
                 Array.Reverse(out_byte_array);


           



        }
        private static int DecodeOTRBytes(byte[] in_byte_array, int start_index, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {

            /* Assumes in byte array is big-endian */
            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecodeOTRBytes: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("DecodeOTRBytes: The OTR data len type is invalid");


            if (start_index < 0)
             throw new ArgumentException("DecodeOTRBytes: The start index cannot be less than 0");

             int _type_length = GetOTRDataLenType(otr_data_len_type);
             int _next_start_index = start_index + _type_length;

            out_byte_array = new byte [_type_length];

            Buffer.BlockCopy(in_byte_array, start_index, out_byte_array, 0, out_byte_array.Length);


            if (BitConverter.IsLittleEndian == true)
                Array.Reverse(out_byte_array);


            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            return _next_start_index;



        }
        
        private static void EncodeBytes(byte[] in_byte_array, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {



            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeBytes: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("EncodeBytes: The OTR data len type is invalid");


            int _type_length = GetOTRDataLenType(otr_data_len_type);

            byte[] _byte_array = new byte[in_byte_array.Length];

            Buffer.BlockCopy(in_byte_array, 0, _byte_array, 0, _byte_array.Length);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(_byte_array);


            byte[] _length_byte_array = new byte[_type_length];
            byte[] _length_temp_array = BitConverter.GetBytes(_byte_array.Length);

            if (BitConverter.IsLittleEndian == false)
                Array.Reverse(_length_temp_array);

            Buffer.BlockCopy(_length_temp_array, 0, _length_byte_array, 0, _length_byte_array.Length);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(_length_byte_array);


            if (_length_byte_array.Length != _type_length)
                throw new InvalidDataException("EncodeOTRBytes: Expected array of length " + _type_length.ToString());


            out_byte_array = new byte[_length_byte_array.Length + _byte_array.Length];


            Buffer.BlockCopy(_length_byte_array, 0, out_byte_array, 0, _type_length);
            Buffer.BlockCopy(_byte_array, 0, out_byte_array, _type_length, _byte_array.Length);




        }
        private static int DecoupleTypeFromBytes(byte[] in_byte_array, int start_index, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {

            if (in_byte_array == null || in_byte_array.Length < 1)
             throw new ArgumentException("DecoupleTypeFromBytes: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("DecoupleTypeFromBytes: The OTR data len type is invalid");


            if (start_index < 0)
                throw new ArgumentException("DecoupleTypeFromBytes: The start index cannot be less than 0");


            int _type_length = GetOTRDataLenType(otr_data_len_type);

            if (in_byte_array.Length < _type_length + 1)
                throw new ArgumentException("DecoupleTypeFromBytes: In byte array length cannot be less than specified type length of " + _type_length.ToString());


            int _next_start_index = 0;


            byte[] _length_byte_array = new byte[_type_length];

            Buffer.BlockCopy(in_byte_array, start_index, _length_byte_array, 0, _type_length);


            if (BitConverter.IsLittleEndian)
             Array.Reverse(_length_byte_array);

            byte[] _int_32_length = new byte[4];
            Buffer.BlockCopy(_length_byte_array, 0, _int_32_length, 0, _length_byte_array.Length);


            int _data_array_length = BitConverter.ToInt32(_int_32_length, 0);

            if (_data_array_length < 1)
                throw new InvalidDataException("DecoupleTypeFromBytes: The length of the data sub array in the in byte array is less than 1");

            _next_start_index = _data_array_length + start_index + _type_length;

            if (_next_start_index > in_byte_array.Length)
                throw new InvalidDataException("DecoupleTypeFromBytes: The extracted data length value exceeds the length of the byte array");

            out_byte_array = new byte[_data_array_length + _type_length];

            Buffer.BlockCopy(in_byte_array, start_index, out_byte_array, 0, out_byte_array.Length);

            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            

            return _next_start_index;






        }
        private static int DecodeBytes(byte[] in_byte_array, int start_index, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {

            //assumes in_byte_array is in bigendian

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecodeBytes: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("DecodeOTRBytes: The OTR data len type is invalid");

            if (start_index < 0)
                throw new ArgumentException("DecodeOTRBytes: The start index cannot be less than 0");


            int _type_length = GetOTRDataLenType(otr_data_len_type);



            if (in_byte_array.Length < _type_length + 1)
                throw new ArgumentException("DecodeOTRBytes: In byte array length cannot be less than specified type length of " + _type_length.ToString());


            int _next_start_index = 0;


            byte[] _length_byte_array = new byte[_type_length];

            Buffer.BlockCopy(in_byte_array, start_index, _length_byte_array, 0, _type_length);



            if (BitConverter.IsLittleEndian)
                Array.Reverse(_length_byte_array);


            byte[] _int_32_length = new byte[4];
            Buffer.BlockCopy(_length_byte_array, 0, _int_32_length, 0, _length_byte_array.Length);


            // int _data_array_length = BitConverter.ToInt16(_length_byte_array, 0);

            int _data_array_length = BitConverter.ToInt32(_int_32_length, 0);




            if (_data_array_length < 1)
                throw new InvalidDataException("DecodeOTRBytes: The length of the data sub array in the in byte array is less than 1");

            _next_start_index = _data_array_length + start_index + _type_length;


            if (_next_start_index > in_byte_array.Length)
                throw new InvalidDataException("DecodeOTRBytes: The extracted data length value exceeds the length of the byte array");

            out_byte_array = new byte[_data_array_length];

            Buffer.BlockCopy(in_byte_array, _type_length, out_byte_array, 0, out_byte_array.Length);



            if (BitConverter.IsLittleEndian)
                Array.Reverse(out_byte_array);


            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            return _next_start_index;


        }


        private static void EncodeBytesBE(byte[] in_byte_array, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {



            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeBytesBE: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("EncodeBytesBE: The OTR data len type is invalid");


            int _type_length = GetOTRDataLenType(otr_data_len_type);

            byte[] _byte_array = new byte[in_byte_array.Length];

            Buffer.BlockCopy(in_byte_array, 0, _byte_array, 0, _byte_array.Length);


            byte[] _length_byte_array = new byte[_type_length];
            byte[] _length_temp_array = BitConverter.GetBytes(_byte_array.Length);

            if (BitConverter.IsLittleEndian == false)
                Array.Reverse(_length_temp_array);

            Buffer.BlockCopy(_length_temp_array, 0, _length_byte_array, 0, _length_byte_array.Length);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(_length_byte_array);


           

            out_byte_array = new byte[_length_byte_array.Length + _byte_array.Length];


            Buffer.BlockCopy(_length_byte_array, 0, out_byte_array, 0, _type_length);
            Buffer.BlockCopy(_byte_array, 0, out_byte_array, _type_length, _byte_array.Length);




        }
        private static int DecodeBytesBE(byte[] in_byte_array, int start_index, OTR_DATA_LEN_TYPE otr_data_len_type, ref byte[] out_byte_array)
        {

            //assumes in_byte_array is in bigendian

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecodeBytesBE: In byte array cannot be null/empty");


            if (otr_data_len_type == OTR_DATA_LEN_TYPE.INVALID)
                throw new ArgumentException("DecodeBytesBE: The OTR data len type is invalid");

            if (start_index < 0)
                throw new ArgumentException("DecodeBytesBE: The start index cannot be less than 0");


            int _type_length = GetOTRDataLenType(otr_data_len_type);



            if (in_byte_array.Length < _type_length + 1)
                throw new ArgumentException("DecodeBytesBE: In byte array length cannot be less than specified type length of " + _type_length.ToString());


            int _next_start_index = 0;


            byte[] _length_byte_array = new byte[_type_length];

            Buffer.BlockCopy(in_byte_array, start_index, _length_byte_array, 0, _type_length);



            if (BitConverter.IsLittleEndian)
                Array.Reverse(_length_byte_array);


            byte[] _int_32_length = new byte[4];
            Buffer.BlockCopy(_length_byte_array, 0, _int_32_length, 0, _length_byte_array.Length);


            int _data_array_length = BitConverter.ToInt32(_int_32_length, 0);



            if (_data_array_length < 1)
                throw new InvalidDataException("DecodeBytesBE: The length of the data sub array in the in byte array is less than 1");

            _next_start_index = _data_array_length + start_index + _type_length;


            if (_next_start_index > in_byte_array.Length)
                throw new InvalidDataException("DecodeBytesBE: The extracted data length value exceeds the length of the byte array");

            out_byte_array = new byte[_data_array_length];

            Buffer.BlockCopy(in_byte_array, _type_length, out_byte_array, 0, out_byte_array.Length);




            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            return _next_start_index;


        }
              
        public static void EncodeOTRCtr(UInt64 counter_value, ref byte[] out_byte_array)
        {
            
            byte [] _counter_bytes = BitConverter.GetBytes(counter_value);
            
            if (_counter_bytes.Length > OTRConstants.TYPE_LEN_CTR)
             throw new ArgumentException("EncodeOTRCtr: In byte array length cannot be greater than " + OTRConstants.TYPE_LEN_CTR.ToString());

            try
            {

                if (BitConverter.IsLittleEndian == true)
                  Array.Reverse(_counter_bytes);
                
                out_byte_array = new byte[OTRConstants.TYPE_LEN_CTR];

                Buffer.BlockCopy(_counter_bytes, 0, out_byte_array, 0, _counter_bytes.Length);
                    
                   
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRCtr:" + ex.ToString());

            }


        }
        public static int DecodeCtrFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {

            if (start_index < 0)
                throw new ArgumentException("DecodeCtrFromBytes: The start index cannot be less than 0");


            int _next_start_index = -1;

            try
            {

                _next_start_index = start_index + OTRConstants.TYPE_LEN_CTR;


                out_byte_array = new byte[OTRConstants.TYPE_LEN_CTR];

                Buffer.BlockCopy(in_byte_array, start_index, out_byte_array, 0, out_byte_array.Length);


                if (_next_start_index == in_byte_array.Length)
                    _next_start_index = -1;



            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeCtrFromBytes:" + ex.ToString());

            }

            return _next_start_index;
        }

        
        
        public static void EncodeOTRMacBE(byte[] in_byte_array, ref byte[] out_byte_array)
        {
            
            /*Do nothing here. Just copy in byte to out byte array
             * MAC results are already in bigendian format
             * 
             */ 

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeOTRMac: In byte array cannot be null/empty");

            if (in_byte_array.Length > OTRConstants.TYPE_LEN_MAC)
             throw new ArgumentException("EncodeOTRMac: In byte array length cannot be greater than " + OTRConstants.TYPE_LEN_MAC.ToString());

            try
            {
                out_byte_array = new byte[OTRConstants.TYPE_LEN_MAC];

                Buffer.BlockCopy(in_byte_array, 0, out_byte_array, 0, in_byte_array.Length);


            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRMac:" + ex.ToString());

            }


        }
        public static int DecodeMacFromBytesBE(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {

            

            if (start_index < 0)
                throw new ArgumentException("DecodeMacFromBytes: The start index cannot be less than 0");


            int _next_start_index = -1;

            try
            {
                
                _next_start_index = start_index + OTRConstants.TYPE_LEN_MAC;

                
                out_byte_array = new byte[OTRConstants.TYPE_LEN_MAC];

                Buffer.BlockCopy(in_byte_array, start_index, out_byte_array, 0, out_byte_array.Length);
              

                if (_next_start_index == in_byte_array.Length)
                    _next_start_index = -1;                
                


            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeMacFromBytes:" + ex.ToString());

            }

            return _next_start_index;
        }
       
               
        
        public static void EncodeOTRByte(byte[] in_byte_array, ref byte[] out_byte_array)
        {
            try
            {
                
                EncodeOTRBytes(in_byte_array, OTR_DATA_LEN_TYPE.TYPE_BYTE, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRBytes:" + ex.ToString());

            }

        }
        public static int DecodeByteFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeOTRBytes(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_BYTE, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeByteFromBytes:" + ex.ToString());

            }


            return _next_start_index;

        }
        

        
        public  static void EncodeMpiBytes(BigInteger big_int_data, ref byte[] out_byte_array)
        {


            try
            {

                EncodeMpiBytes(big_int_data.ToByteArray(), ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeMpiBytes:" + ex.ToString());

            }

        }    
        public  static void EncodeMpiBytes(byte[] in_byte_array, ref byte[] out_byte_array)
        {

            if (in_byte_array == null || in_byte_array.Length < 1)
            throw new ArgumentException("EncodeMpiBytes: In byte array cannot be null/empty");


            byte[] _byte_array = null;

            try
            {

                _byte_array = new byte[in_byte_array.Length];
                Buffer.BlockCopy(in_byte_array, 0, _byte_array, 0, in_byte_array.Length);

                SetAsMinimalLength(ref _byte_array);

                EncodeBytes(_byte_array, OTR_DATA_LEN_TYPE.TYPE_MPI, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeMpiBytes:" + ex.ToString());

            }

        }
        public  static int DecodeMpiFromBytes(byte[] mpi_byte_array, int start_index, ref byte[] out_byte_array)
        {


            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeBytes(mpi_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_MPI, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeMpiFromBytes:" + ex.ToString());

            }


            return _next_start_index;

        }
        public  static int DecodeMpiFromBytes(byte[] mpi_byte_array, int start_index, ref BigInteger out_big_int)
        {

            byte[] _out_byte_array = null;
            int _next_start_index = DecodeMpiFromBytes(mpi_byte_array, start_index, ref _out_byte_array);


            if (_out_byte_array[0] > 0)
                out_big_int = new BigInteger(NormalizeBigInt(_out_byte_array)); //it is negative
            else
                out_big_int = new BigInteger(_out_byte_array);


            return _next_start_index;
        }   
        public  static int DecoupleMpiFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;
            try
            {
                _next_start_index = DecoupleTypeFromBytes(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_MPI, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecoupleMpiFromBytes:" + ex.ToString());

            }


            return _next_start_index;

        }
        public  static void SetAsMinimalLength(ref byte[] data_byte_array)
        {
            // asummes byte array is coming in as little endian 

            if (data_byte_array == null || data_byte_array.Length < 1)
                throw new ArgumentException("SetMinimalLength: Data byte array cannot be null/empty");

            byte[] _byte_array = null;


            if (BitConverter.IsLittleEndian == true)
            {
                if (data_byte_array[data_byte_array.Length - 1] < 1)
                {
                    _byte_array = new byte[data_byte_array.Length - 1];
                    Buffer.BlockCopy(data_byte_array, 0, _byte_array, 0, _byte_array.Length);

                }
                else
                {
                    _byte_array = new byte[data_byte_array.Length];
                    Buffer.BlockCopy(data_byte_array, 0, _byte_array, 0, _byte_array.Length);

                }
            }
            else
            {

                if (data_byte_array[0] < 1)
                {
                    _byte_array = new byte[data_byte_array.Length - 1];
                    Buffer.BlockCopy(data_byte_array, 1, _byte_array, 0, _byte_array.Length);

                }
                else
                {

                    _byte_array = new byte[data_byte_array.Length];
                    Buffer.BlockCopy(data_byte_array, 0, _byte_array, 0, _byte_array.Length);

                }
            }


            data_byte_array = new byte[_byte_array.Length];

            Buffer.BlockCopy(_byte_array, 0, data_byte_array, 0, data_byte_array.Length);


        }
        public static byte[] NormalizeBigInt(byte[] in_byte_array)
        {

            //Assumes input is little endian
            // when big int is made minimal length i.e., the removal of the leading zero
            // it turns the big int value to negative. This function normalizes it.

            if (in_byte_array == null || in_byte_array.Length < 1)
                return in_byte_array;


            byte[] _byte_array = new byte[in_byte_array.Length + 1];

            _byte_array[in_byte_array.Length] = 0;


            Buffer.BlockCopy(in_byte_array, 0, _byte_array, 0, in_byte_array.Length);

            return _byte_array;




        }

        
        public static void EncodeMpiBytes(Org.BouncyCastle.Math.BigInteger big_int_data, ref byte[] out_byte_array)
        {


            try
            {

                EncodeMpiBytesBE(big_int_data.ToByteArray(), ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeMpiBytes:" + ex.ToString());

            }

        }        
        public static int DecodeMpiFromBytes(byte[] mpi_byte_array, int start_index, ref Org.BouncyCastle.Math.BigInteger out_big_int)
        {

            byte[] _out_byte_array = null;
            int _next_start_index = DecodeMpiFromBytesBE(mpi_byte_array, start_index, ref _out_byte_array);

            out_big_int = new Org.BouncyCastle.Math.BigInteger(1, _out_byte_array);


            return _next_start_index;
        }
       
       
        private static void  EncodeMpiBytesBE(byte[] in_byte_array, ref byte[] out_byte_array)
        {

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeMpiBytes: In byte array cannot be null/empty");


            byte[] _byte_array = null;

            try
            {

                _byte_array = new byte[in_byte_array.Length];
                Buffer.BlockCopy(in_byte_array, 0, _byte_array, 0, in_byte_array.Length);

                SetAsMinimalLengthBE(ref _byte_array);

                EncodeBytesBE(_byte_array, OTR_DATA_LEN_TYPE.TYPE_MPI, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeMpiBytes:" + ex.ToString());

            }

        }              
        private static int   DecodeMpiFromBytesBE(byte[] mpi_byte_array, int start_index, ref byte[] out_byte_array)
        {


            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeBytesBE(mpi_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_MPI, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeMpiFromBytesBigEndian:" + ex.ToString());

            }


            return _next_start_index;

        }  
        public static void SetAsMinimalLengthBE(ref byte[] in_byte_array)
        {
            byte[] _byte_array = null;

            if (in_byte_array[0] < 1)
            {
                _byte_array = new byte[in_byte_array.Length - 1];
                Buffer.BlockCopy(in_byte_array, 1, _byte_array, 0, _byte_array.Length);
                in_byte_array = new byte[_byte_array.Length];
                Buffer.BlockCopy(_byte_array, 0, in_byte_array, 0, in_byte_array.Length);

            }
            
           

        }
       

        public static void EncodeOTRInt(byte[] in_byte_array, ref byte[] out_byte_array)
        {


            try
            {

                EncodeOTRBytes(in_byte_array, OTR_DATA_LEN_TYPE.TYPE_INT, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRInt:" + ex.ToString());

            }

        }
        public static int DecodeIntFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeOTRBytes(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_INT, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeIntFromBytes:" + ex.ToString());

            }


            return _next_start_index;

        }
       
        
        public static void EncodeOTRShort(byte[] in_byte_array, ref byte[] out_byte_array)
        {


            try
            {
                EncodeOTRBytes(in_byte_array, OTR_DATA_LEN_TYPE.TYPE_SHORT, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRShort:" + ex.ToString());

            }


        }       
        public static int DecodeShortFromBytes(byte[] int_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeOTRBytes(int_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_SHORT, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeShortFromByte:" + ex.ToString());

            }


            return _next_start_index;

        }
       

        public static void EncodeOTRData(byte[] in_byte_array, ref byte[] out_byte_array)
        {
            try
            {
                EncodeBytes(in_byte_array, OTR_DATA_LEN_TYPE.TYPE_DATA, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRData:" + ex.ToString());

            }



        }
        public static int DecodeDataFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeBytes(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_DATA, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeDataFromByte:" + ex.ToString());

            }


            return _next_start_index;

        }
        public static int DecoupleDataFromBytes(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;
            try
            {
                _next_start_index = DecoupleTypeFromBytes(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_DATA, ref out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecoupleDataFromBytes:" + ex.ToString());

            }


            return _next_start_index;

        }

        public static void EncodeOTRDataBE(byte[] in_byte_array, ref byte[] out_byte_array)
        {
            try
            {
                EncodeBytesBE(in_byte_array, OTR_DATA_LEN_TYPE.TYPE_DATA, ref out_byte_array);
               
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeOTRDataBE:" + ex.ToString());

            }



        }
        public static int DecodeDataFromBytesBE(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            int _next_start_index = -1;

            try
            {
                _next_start_index = DecodeBytesBE(in_byte_array, start_index, OTR_DATA_LEN_TYPE.TYPE_DATA, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeDataFromByteBE:" + ex.ToString());

            }


            return _next_start_index;

        }
       
        
        
        #endregion

        #region  TLV Encoding functions


        public static void EncodeTLV(byte[] in_byte_array, OTR_TLV_TYPE tlv_type, ref byte[] out_byte_array)
        {

            
            if (tlv_type == OTR_TLV_TYPE.INVALID)
                throw new ArgumentException("EncodeTLV: The TLV type is invalid");

            UInt16 _tlv_type = GetTLVType(tlv_type);

          
            if (_tlv_type < 0 || _tlv_type > 8)
                throw new ArgumentException("EncodeTLV: The TLV type value must be greater than 0 and less than 9");

            
            byte[] _encoded_type = null;
            byte[] _encoded_length = null;
            byte[] _temp_buffer = null;

            UInt16 _tlv_value_length = 0;


            _temp_buffer = BitConverter.GetBytes(_tlv_type);
            EncodeOTRShort(_temp_buffer, ref _encoded_type);


            if (in_byte_array != null && in_byte_array.Length > 1)
             _tlv_value_length = (UInt16)in_byte_array.Length;

            _temp_buffer = BitConverter.GetBytes(_tlv_value_length);                
             EncodeOTRShort(_temp_buffer, ref _encoded_length);

                         
                out_byte_array = new byte[_encoded_type.Length + _encoded_length.Length + _tlv_value_length];

                Buffer.BlockCopy(_encoded_type, 0, out_byte_array, 0, _encoded_type.Length);
                Buffer.BlockCopy(_encoded_length, 0, out_byte_array, _encoded_type.Length, _encoded_length.Length);

            
                if (_tlv_value_length > 0)
                {
                    if (BitConverter.IsLittleEndian == true)
                    Buffer.BlockCopy(in_byte_array.Reverse().ToArray(), 0, out_byte_array, _encoded_type.Length + _encoded_length.Length, in_byte_array.Length);
                    else
                    Buffer.BlockCopy(in_byte_array, 0, out_byte_array, _encoded_type.Length + _encoded_length.Length, in_byte_array.Length);

                }
            
               
               

        }
        public static int DecodeTLV(byte[] in_byte_array, int start_index,ref byte[] out_byte_array)
        {
            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecodeTLV: The in byte array cannot be null/empty");

            byte[] _decoded_type = null;
            byte[] _decoded_length = null;

            int _next_start_index = start_index;


            UInt16 _data_length = 0;

            try
            {
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_type);

               
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_length);
                _data_length = BitConverter.ToUInt16(_decoded_length, 0);

                if (_data_length > 0)
                {

                    out_byte_array = new byte[_data_length];

                    Buffer.BlockCopy(in_byte_array, _next_start_index, out_byte_array, 0, out_byte_array.Length);

                       if (BitConverter.IsLittleEndian == true)
                        Array.Reverse(out_byte_array);

                    _next_start_index += _data_length;
                }


            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeTLV:" + ex.ToString());

            }


            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            return _next_start_index;


        }
        public static int DecoupleTLV(byte[] in_byte_array, int start_index, ref byte[] out_byte_array)
        {
            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecoupleTLV: The in byte array cannot be null/empty");



            int _next_start_index = start_index;
            byte[] _decoded_length = null;


            UInt16 _data_length = 0;

            try
            {

                _next_start_index = DecodeShortFromBytes(in_byte_array, start_index + 2, ref _decoded_length);//Skip the type byte
                _data_length = BitConverter.ToUInt16(_decoded_length, 0);

                if (_data_length > 0)
                {
                    out_byte_array = new byte[_data_length + 4]; //Plus type (2 bytes) and Length (2 bytes)
                    Buffer.BlockCopy(in_byte_array, start_index, out_byte_array, 0, out_byte_array.Length);
                    _next_start_index = out_byte_array.Length;


                }
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecoupleTLV:" + ex.ToString());

            }

            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;


            return _next_start_index;

        }
       

       
        public static void EncodeTLVPadding(byte[] in_byte_array, ref byte[] out_byte_array)
        {

            try
            {
                
                 EncodeTLV(in_byte_array, OTR_TLV_TYPE.PADDING, ref out_byte_array);
                
                
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVPadding:" + ex.ToString());

            }

        }      
        public static int  DecodeTLVPadding(byte[] in_byte_array, int start_index)
        {

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("DecodeTLVPadding: The in byte array cannot be null/empty");

            byte[] _decoded_type = null;
            byte[] _decoded_length = null;

            int _next_start_index = start_index;


            UInt16 _data_length = 0;

            try
            {
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_type);
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_length);
                _data_length = BitConverter.ToUInt16(_decoded_length, 0);

               
                _next_start_index += _data_length;


            }
            catch (Exception ex)
            {

                throw new InvalidDataException("DecodeTLVPadding:" + ex.ToString());

            }


             return _next_start_index;

           

        }
        public static void EncodeTLVExtraSymKey(byte[] in_byte_array, ref byte[] out_byte_array)
        {

           // if (in_byte_array == null || in_byte_array.Length < 1)
               // throw new ArgumentException("EncodeTLVExtraSymKey: The in byte array cannot be null/empty");



            try
            {
                
                EncodeTLV(in_byte_array, OTR_TLV_TYPE.EXTRA_SYM_KEY, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVExtraSymKey:" + ex.ToString());

            }

        }
        public static void EncodeTLVDisconnected(ref byte[] out_byte_array)
        {

            
            try
            {
               
                
                EncodeTLV(null, OTR_TLV_TYPE.DISCONNECTED, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVDisconnected:" + ex.ToString());

            }

        }
        public static void EncodeTLVSMP1Q(byte[] in_byte_array, ref byte[] out_byte_array)
        {

            if (in_byte_array == null || in_byte_array.Length < 1)
                throw new ArgumentException("EncodeTLVDisconnected: The in byte array cannot be null/empty");

            try
            {
                
                EncodeTLV(in_byte_array, OTR_TLV_TYPE.SMP_MESSAGE_1Q, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVDisconnected:" + ex.ToString());

            }

        }
        public static void EncodeTLVSMPAbort(ref byte[] out_byte_array)
        {

            
            try
            {
                
                EncodeTLV(null, OTR_TLV_TYPE.SMP_ABORT, ref out_byte_array);

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVSMPAbort:" + ex.ToString());

            }

        }


        public static void EncodeTLVSMPMessage(OTR_TLV_TYPE tlv_type,UInt32 mpi_count, byte[] mpi_byte_arrays,ref byte[] out_byte_array)
        {

            if (mpi_byte_arrays == null || mpi_byte_arrays.Length < 1)
            throw new ArgumentException("EncodeTLVSMPMesage: The in byte array cannot be null/empty");

            
            if (mpi_count < 1)
            throw new ArgumentException("EncodeTLVSMPMessage: The TLV type value must be greater than 1");


            UInt16 _tlv_type = GetTLVType(tlv_type);

            if (_tlv_type < 2 || _tlv_type > 5)
            throw new ArgumentException("EncodeTLVSMPMessage: The TLV type value must be greater than 2 and less than 6");


            byte[] _encoded_type = null;
            byte[] _encoded_length = null;
            byte[] _encoded_mpi_count = null;
            byte[] _temp_buffer = null;



            try
            {

                _temp_buffer = BitConverter.GetBytes(_tlv_type);
                EncodeOTRShort(_temp_buffer, ref _encoded_type);

                _temp_buffer = BitConverter.GetBytes(mpi_count);
                EncodeOTRInt(_temp_buffer, ref _encoded_mpi_count);

              

                _temp_buffer = BitConverter.GetBytes((UInt16)(mpi_byte_arrays.Length + _encoded_mpi_count.Length));
                EncodeOTRShort(_temp_buffer, ref _encoded_length);

               
                out_byte_array = new byte[_encoded_type.Length + _encoded_length.Length + _encoded_mpi_count.Length + mpi_byte_arrays.Length];

                Buffer.BlockCopy(_encoded_type, 0, out_byte_array, 0, _encoded_type.Length);
                Buffer.BlockCopy(_encoded_length, 0, out_byte_array, _encoded_type.Length, _encoded_length.Length);
                Buffer.BlockCopy(_encoded_mpi_count, 0, out_byte_array, _encoded_type.Length + _encoded_length.Length, _encoded_mpi_count.Length);
                Buffer.BlockCopy(mpi_byte_arrays, 0, out_byte_array, _encoded_type.Length + _encoded_length.Length + _encoded_mpi_count.Length, mpi_byte_arrays.Length);
                              

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVSMPMessage:" + ex.ToString());

            }
        }
        public static int DecodeTLVSMPMessage(byte[] in_byte_array, int start_index, ref UInt32 mpi_count,ref byte[] mpi_byte_arrays)
        {
            if (in_byte_array == null || in_byte_array.Length < 1)
             throw new ArgumentException("DecodeTLVSMPMessage: The in byte array cannot be null/empty");

            byte[] _decoded_type_array = null;
            byte[] _decoded_length_array = null;
            byte[] _mpi_count_array = null;

            int _next_start_index = start_index;

            UInt16 _data_length = 0;
            
            
           



            try
            {
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_type_array);
                _next_start_index = DecodeShortFromBytes(in_byte_array, _next_start_index, ref _decoded_length_array);
                _data_length = BitConverter.ToUInt16(_decoded_length_array, 0);

                if (_data_length < 5)
                 throw new ArgumentException("DecodeTLVSMPMessage: The TLV length cannot be less than 5");

                _next_start_index = DecodeIntFromBytes(in_byte_array, _next_start_index, ref _mpi_count_array);
                mpi_count = BitConverter.ToUInt32(_mpi_count_array, 0);

                if (mpi_count < 1)
                throw new ArgumentException("DecodeTLVSMPMessage: The TLV mpi count cannot be less than 1");

                               
                mpi_byte_arrays = new byte[in_byte_array.Length - _next_start_index];

               Buffer.BlockCopy(in_byte_array, _next_start_index, mpi_byte_arrays, 0, mpi_byte_arrays.Length);

                _next_start_index += mpi_byte_arrays.Length;
                

            }
            catch (Exception ex)
            {

                throw new InvalidDataException("EncodeTLVSMPMessage:" + ex.ToString());

            }

            if (_next_start_index == in_byte_array.Length)
                _next_start_index = -1;

            return _next_start_index;
        }

        
        
        #endregion

        #region  Misc functions

        public static bool IsValidPublicKey(BigInteger public_key)
        {
            if (OTRConstants.RFC_3526_GENERATOR <= public_key && public_key <= OTRConstants.RFC_3526_PRIME_MODULO_MINUS_TWO())
                return true;

            return false;

        }
        public static bool IsValidPublicKey(byte[] public_key_byte_array)
        {

            if (public_key_byte_array == null || public_key_byte_array.Length < 1)
                throw new ArgumentException("IsValidPublicKey: Public key byte array cannot be null/empty");


            byte[] _byte_array = null;

            BigInteger _public_key;

            if (BitConverter.IsLittleEndian)
                _byte_array = public_key_byte_array.Reverse().ToArray();
            else
            {
                _byte_array = new byte[public_key_byte_array.Length];
                Buffer.BlockCopy(public_key_byte_array, 0, _byte_array, 0, public_key_byte_array.Length);
            }


            if (_byte_array[0] != 0)
                _public_key = new BigInteger(NormalizeBigInt(_byte_array));
            else
                _public_key = new BigInteger(_byte_array);


            return IsValidPublicKey(_public_key);

        }
        public static BigInteger ComputeSecret(DHKeyPair my_key_pair, BigInteger public_key, BigInteger generator, BigInteger prime_modulo)
        {

            if (my_key_pair == null)
                throw new ArgumentException("ComputeSecret:  My Key Pair cannot be null");

            if (my_key_pair.GetPrivateKey() < 1)
                throw new ArgumentException("ComputeSecret: Private key in my_key_pair value cannot be less than 0");

            if (public_key < 1)
                throw new ArgumentException("ComputeSecret: Public key value cannot be less than 0");

            if (generator < 1)
                throw new ArgumentException("ComputeSecret: Generator value cannot be less than 0");

            if (prime_modulo < 1)
                throw new ArgumentException("ComputeSecret: Prime Modulo value cannot be less than 0");

            return BigInteger.ModPow(public_key, my_key_pair.GetPrivateKey(), prime_modulo);

        }
        public static void SetSecByteMpi(BigInteger secret, ref byte[] sec_data_byte_array)
        {

            byte[] _out_byte_array = null;

            try
            {
                EncodeMpiBytes(secret, ref  _out_byte_array);
            }
            catch (Exception ex)
            {

                throw new InvalidDataException("SetSecByteMpi:" + ex.ToString());

            }


            if (_out_byte_array == null)
                throw new ArgumentException("SetSecByteMpi: _out_byte_array cannot be null");

            sec_data_byte_array = new byte[_out_byte_array.Length + 1];

            Buffer.BlockCopy(_out_byte_array, 0, sec_data_byte_array, 1, _out_byte_array.Length);



            // for (int i = 0; i < sec_data_byte_array.Length; i++)            
            // Console.WriteLine("Sec data byte Index:{0}  Byte:{1}", i, sec_data_byte_array[i]);

        }
        
         public static string ByteToHex(byte[] byte_array)
        {
            string _hex_string = string.Empty;

            foreach (byte _byte in byte_array)
            {
                _hex_string += String.Format("{0:x2}", _byte);
            }

            return _hex_string;


        }

        private static int GetOTRDataLenType(OTR_DATA_LEN_TYPE otr_data_type)
        {
            

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_CTR)
                return OTRConstants.TYPE_LEN_CTR;

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_INT)
                return OTRConstants.TYPE_LEN_INT;

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_MAC)
                return OTRConstants.TYPE_LEN_MAC;

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_MPI)
                return OTRConstants.TYPE_LEN_MPI;

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_SHORT)
                return OTRConstants.TYPE_LEN_SHORT;


            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_DATA)
                return OTRConstants.TYPE_LEN_DATA;

            if (otr_data_type == OTR_DATA_LEN_TYPE.TYPE_BYTE)
                return OTRConstants.TYPE_LEN_BYTE;

            


            return -1;


        }

        private static UInt16 GetTLVType(OTR_TLV_TYPE tlv_type)
        {

           
            if (tlv_type == OTR_TLV_TYPE.PADDING)
             return OTRConstants.TLV_TYPE_PADDING;


            if (tlv_type == OTR_TLV_TYPE.DISCONNECTED)
             return OTRConstants.TLV_TYPE_DISCONNECTED;


            if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_1)
            return OTRConstants.TLV_TYPE_SMP_MSG_1;

            if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_2)
                return OTRConstants.TLV_TYPE_SMP_MSG_2;

            if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_3)
                return OTRConstants.TLV_TYPE_SMP_MSG_3;

            if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_4)
                return OTRConstants.TLV_TYPE_SMP_MSG_4;

            if (tlv_type == OTR_TLV_TYPE.SMP_ABORT)
                return OTRConstants.TLV_TYPE_SMP_ABORT;

            if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_1Q)
                return OTRConstants.TLV_TYPE_SMP_1Q;


            if (tlv_type == OTR_TLV_TYPE.EXTRA_SYM_KEY)
                return OTRConstants.TLV_TYPE_EXTRA_SYM_KEY;


            return 100;

        }
                
        public static OTR_TLV_TYPE GetTLVType(UInt16 tlv_type)
        {


            if (tlv_type == OTRConstants.TLV_TYPE_PADDING)
                return OTR_TLV_TYPE.PADDING;

            if (tlv_type == OTRConstants.TLV_TYPE_DISCONNECTED)
                return OTR_TLV_TYPE.DISCONNECTED;


            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_1)
                return OTR_TLV_TYPE.SMP_MESSAGE_1;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_2)
                return OTR_TLV_TYPE.SMP_MESSAGE_2;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_3)
                return OTR_TLV_TYPE.SMP_MESSAGE_3;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_4)
                return OTR_TLV_TYPE.SMP_MESSAGE_4;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_ABORT)
                return OTR_TLV_TYPE.SMP_ABORT;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_1Q)
                return OTR_TLV_TYPE.SMP_MESSAGE_1Q;

            if (tlv_type == OTRConstants.TLV_TYPE_EXTRA_SYM_KEY)
                return OTR_TLV_TYPE.EXTRA_SYM_KEY;


            return OTR_TLV_TYPE.INVALID;


        }
        
        public static bool IsTlvType(Int16 tlv_type)
        {
            if (tlv_type == OTRConstants.TLV_TYPE_PADDING)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_DISCONNECTED)
                return true;


            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_1)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_2)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_3)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_4)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_ABORT)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_1Q)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_EXTRA_SYM_KEY)
                return true;

            return false;
        }
               
        private static bool IsSmpTlvType(int tlv_type)
        {


            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_1)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_2)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_3)
                return true;

            if (tlv_type == OTRConstants.TLV_TYPE_SMP_MSG_4)
                return true;



            return false;
        }


        public static void GetEncodedOtrVersion(OTR_VERSION version, ref byte[] encoded_otr_version_byte_array)
        {
            if (version == OTR_VERSION.INVALID)
                return;

            byte [] _temp_buffer = null;
            byte [] _otr_version = new byte [2];

            
             if (version == OTR_VERSION.VERSION_2)
             { 
             _temp_buffer = BitConverter.GetBytes(OTRConstants.iOTR_VERSION_2);
              Buffer.BlockCopy (_temp_buffer,0,_otr_version,0,_otr_version.Length);
             }
             else if (version == OTR_VERSION.VERSION_3)
             {
              _temp_buffer = BitConverter.GetBytes(OTRConstants.iOTR_VERSION_3);
              Buffer.BlockCopy (_temp_buffer,0,_otr_version,0,_otr_version.Length);
             }



           
            
            if (_otr_version == null || _otr_version.Length < 1)
            return;
            

            Utility.EncodeOTRShort(_otr_version, ref encoded_otr_version_byte_array);


        }      
        public static OTR_VERSION GetOTRVersion(byte[] otr_version_byte_array)
        {
            if (otr_version_byte_array == null || otr_version_byte_array.Length < 1)
                return OTR_VERSION.INVALID;


            byte[] _otr_version_bytes = new byte[4];
            Buffer.BlockCopy(otr_version_byte_array, 0, _otr_version_bytes, 0, otr_version_byte_array.Length);

            int _otr_version_int = BitConverter.ToInt32(_otr_version_bytes, 0);

            if (_otr_version_int == OTRConstants.iOTR_VERSION_2)
                return OTR_VERSION.VERSION_2;

            if (_otr_version_int == OTRConstants.iOTR_VERSION_3)
                return OTR_VERSION.VERSION_3;
          

            return OTR_VERSION.INVALID;


        }
        public static OTR_VERSION GetOTRVersion(string otr_version)
        {
            

            if (string.IsNullOrEmpty(otr_version))
                return OTR_VERSION.INVALID;


            if (otr_version.Equals(OTRConstants.OTR_VERSION_2) || otr_version.Equals(OTRConstants.OTR_VERSION_1_2))         
                return OTR_VERSION.VERSION_2;


            if (otr_version.Equals(OTRConstants.OTR_VERSION_3) || otr_version.Equals(OTRConstants.OTR_VERSION_2_AND_3))
                return OTR_VERSION.VERSION_3;

          


            return OTR_VERSION.INVALID;


        }
                 
             
        public static bool IsStringExist (string string_data, string sub_string)
        {
            int _position = string_data.IndexOf(sub_string);

            if (_position > -1)
                return true;
            else
               return false;
                       
         }
        public static bool IsArrayEqual(byte[] byte_array_a, byte[] byte_array_b)
       {
           /* TODO: Find a more efficient way to compare byte arrays */


           if (byte_array_a == null || byte_array_b.Length < 1)
               return false;

           if (byte_array_b == null || byte_array_b.Length < 1)
               return false;

           string _array_string_64_a = Convert.ToBase64String(byte_array_a);
           string _array_string_64_b = Convert.ToBase64String(byte_array_b);

           return _array_string_64_b.Equals(_array_string_64_a);

       }
       
       
       #endregion

         
    }

   

   
}