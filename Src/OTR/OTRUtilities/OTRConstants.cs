using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.Numerics;
using System.Globalization;
using System.IO;

namespace OTR.Utilities
{
    class OTRConstants
    {
        

        const string RFC_3526_GENERATOR_TEXT     = "2";
       // const UInt32 PRIVATE_KEY_MIN_LENGTH      = 320;
        public const int SMP_RAND_EXP_LENGTH_BITS = 1536;
        public const int SMP_RAND_EXP_LENGTH_BYTES = 192;


        public const byte OTR_VERSION = 0x0003;


        public static BigInteger   RFC_3526_GENERATOR = BigInteger.Parse(RFC_3526_GENERATOR_TEXT);
        private static BigInteger  PRIME_MODULO = 0;
        private static BigInteger  PRIME_MODULO_MINUS_2 = 0;
        private static BigInteger  PRIME_SMP_MODULO = 0;

        private static string MODULO = string.Empty;
        private static string MODULO_MINUS_2 = string.Empty;
        private static string SMP_MODULO = string.Empty;

       


        public const int DH_PRIVATE_KEY_MINIMUM_LENGTH_BITS = 320;
        public const int AES_KEY_LENGTH_BITS = 128;
        public const int MAC_KEY_LENGTH_BITS = 256;


        
        public const int AES_SEND_KEY_LENGTH_BITS = 128;
        public const int AES_RECV_KEY_LENGTH_BITS = 128;
        public const int MAC_SEND_KEY_LENGTH_BITS = 160;
        public const int MAC_RECV_KEY_LENGTH_BITS = 160;
        public const int MAC_SIGNATURE_LENGTH_BITS = 160;

        public const int AES_EXTRA_KEY_LENGTH_BITS = 256;


        public const byte SESS_ID_FIRST_BYTE_VALUE = 0x00;
        public const byte AES_KEYS_FIRST_BYTE_VALUE = 0x01;
        public const byte MAC_KEY_1_FIRST_BYTE_VALUE = 0x02;
        public const byte MAC_KEY_2_FIRST_BYTE_VALUE = 0x03;
        public const byte MAC_KEY_3_FIRST_BYTE_VALUE = 0x04;
        public const byte MAC_KEY_4_FIRST_BYTE_VALUE = 0x05;


        public const byte AES_EXTRA_KEY_FIRST_BYTE_VALUE = 0xFF;
        public const UInt16 DSA_PUB_KEY_TYPE             = 0;

        
        public const byte HIGH_END_SEND_BYTE_VALUE = 0x01;
        public const byte HIGH_END_RECV_BYTE_VALUE = 0x02;
        public const byte LOW_END_SEND_BYTE_VALUE  = 0x02;
        public const byte LOW_END_RECV_BYTE_VALUE  = 0x01;


        public const int TYPE_LEN_BYTE = 1;
        public const int TYPE_LEN_SHORT = 2;
        public const int TYPE_LEN_INT = 4;
        public const int TYPE_LEN_MPI = 4;
        public const int TYPE_LEN_DATA = 4;
        public const int TYPE_LEN_MAC = 20;
        public const int TYPE_LEN_CTR = 8;



        public const byte MESSAGE_TYPE_DH_COMMIT        = 2; // 0x02;
        public const byte MESSAGE_TYPE_DH_KEY           = 10; //0x0a;
        public const byte MESSAGE_TYPE_REVEAL_SIGNATURE = 17; //0x11;
        public const byte MESSAGE_TYPE_SIGNATURE        = 18; //0x12;
        public const byte MESSAGE_TYPE_DATA             = 3; //0x03;

        public const byte MESSAGE_NULL_BYTE             = 0; //0x00;


        public const int IGNORE_UNREADABLE = 1; // 0x01 Data message flag


        public const string OTR_VERSION_1       = "?OTR?";
        public const string OTR_VERSION_1_2     = "?OTR?v2?";
        public const string OTR_VERSION_2       = "?OTRv2?";
        public const string OTR_VERSION_3       = "?OTRv3?";
        public const string OTR_VERSION_2_AND_3 = "?OTRv23?";
        public const string OTR_VERSION_1_AND_2 = "?OTR?v2?";


        public const int    iOTR_VERSION_2      = 2;
        public const int    iOTR_VERSION_3      = 3;

        public const string OTR_ERROR           = "?OTR Error:";
        public const string OTR_MESSAGE_HEADER  = "?OTR:";
        public const string OTR_MESSAGE_FOOTER  = ".";
        public const string OTR_FRAGMENT_HEADER = "?OTR";
        public const string OTR_FRAGMENT_FOOTER = ",";
       
        public const int MIN_INSTANCE_VALUE = 4;



        public const byte SMP_VERSION = 1; //0x01;

        public const UInt16 TLV_TYPE_PADDING       = 0;
        public const UInt16 TLV_TYPE_DISCONNECTED  = 1;
        public const UInt16 TLV_TYPE_SMP_MSG_1     = 2;
        public const UInt16 TLV_TYPE_SMP_MSG_2     = 3;
        public const UInt16 TLV_TYPE_SMP_MSG_3     = 4;
        public const UInt16 TLV_TYPE_SMP_MSG_4     = 5;
        public const UInt16 TLV_TYPE_SMP_ABORT     = 6;
        public const UInt16 TLV_TYPE_SMP_1Q        = 7;
        public const UInt16 TLV_TYPE_EXTRA_SYM_KEY = 8;


       private static List<string> _otr_version_supported = null;


        private static bool is_hex_strings_set = false;

        public static BigInteger RFC_3526_PRIME_MODULO()
        {
            if (is_hex_strings_set == false)
                SetModuloStrings();

            if (PRIME_MODULO == 0)            
            PRIME_MODULO = BigInteger.Parse(MODULO, NumberStyles.HexNumber);

               
            

            

            return PRIME_MODULO;



        }

        public static BigInteger RFC_3526_PRIME_MODULO_MINUS_TWO()
        {
            if (is_hex_strings_set == false)
                SetModuloStrings();


            if (PRIME_MODULO_MINUS_2 == 0)           
            PRIME_MODULO_MINUS_2 = BigInteger.Parse(MODULO_MINUS_2, NumberStyles.HexNumber);

               
            


            return PRIME_MODULO_MINUS_2;

            
           


        }

        public static BigInteger SMP_PRIME_MODULO()
        {
            if (is_hex_strings_set == false)
                SetModuloStrings();


            if (PRIME_SMP_MODULO == 0)
               PRIME_SMP_MODULO = BigInteger.Parse(SMP_MODULO, NumberStyles.HexNumber);



            return PRIME_SMP_MODULO;

        }

        private static void SetModuloStrings ()
        {
           
            MODULO = "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1";
            MODULO += "29024E088A67CC74020BBEA63B139B22514A08798E3404DD";
            MODULO += "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245";
            MODULO += "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED";
            MODULO += "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D";
            MODULO += "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F";
            MODULO += "83655D23DCA3AD961C62F356208552BB9ED529077096966D";
            MODULO += "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";


            MODULO_MINUS_2 = "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1";
            MODULO_MINUS_2 += "29024E088A67CC74020BBEA63B139B22514A08798E3404DD";
            MODULO_MINUS_2 += "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245";
            MODULO_MINUS_2 += "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED";
            MODULO_MINUS_2 += "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D";
            MODULO_MINUS_2 += "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F";
            MODULO_MINUS_2 += "83655D23DCA3AD961C62F356208552BB9ED529077096966D";
            MODULO_MINUS_2 += "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD";

            

            SMP_MODULO = "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68";
            SMP_MODULO += "948127044533E63A0105DF531D89CD9128A5043CC71A026E";
            SMP_MODULO += "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122";
            SMP_MODULO += "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6";
            SMP_MODULO += "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E";
            SMP_MODULO += "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF";
            SMP_MODULO += "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36";
            SMP_MODULO += "B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF";


            is_hex_strings_set = true;


        }

        public static List<string> VERSION_LIST()
        {
            if (_otr_version_supported == null)
            {
                _otr_version_supported = new List<string>();
                //OTR_VERSIONS_SUPPORTED.Add(OTRConstants.OTR_VERSION_1);
                //OTR_VERSIONS_SUPPORTED.Add(OTRConstants.OTR_VERSION_1_2);
                _otr_version_supported.Add(OTRConstants.OTR_VERSION_2);
                _otr_version_supported.Add(OTRConstants.OTR_VERSION_3);
                _otr_version_supported.Add(OTRConstants.OTR_VERSION_2_AND_3);
                // OTR_VERSIONS_SUPPORTED.Add(OTRConstants.OTR_VERSION_1_AND_2);
            }


            return _otr_version_supported;
        }
   
    
    
    }


    #region Enums

    enum OTR_END_TYPE
    {
        HIGH_END,
        LOW_END,
        INVALID

    }

    enum OTR_MESSAGE_TYPE
    {
        DH_COMMIT,
        DH_KEY,
        REVEAL_SIGNATURE,
        SIGNATURE,
        DATA,
        INVALID

    }

    enum OTR_DATA_LEN_TYPE
    {
        TYPE_MPI,
        TYPE_INT,
        TYPE_SHORT,
        TYPE_MAC,
        TYPE_CTR,
        TYPE_BYTE,
        TYPE_DATA,
        INVALID
    }
    
    enum OTR_AUTH_STATE
    {
        AUTH_STATE_NONE,
        AUTH_STATE_AWAITING_DH_KEY,
        AUTH_STATE_AWAITING_REVEAL_SIG,
        AUTH_STATE_AWAITING_SIG,        
       

    }

    public enum OTR_MESSAGE_STATE
    {
        MSG_STATE_PLAINTEXT,
        MSG_STATE_ENCRYPTED,
        MSG_STATE_FINISHED,
        INVALID
      

    }

    enum OTR_TLV_TYPE
    {
        PADDING,
        DISCONNECTED,
        SMP_MESSAGE_1,
        SMP_MESSAGE_2,
        SMP_MESSAGE_3,
        SMP_MESSAGE_4,
        SMP_ABORT,
        SMP_MESSAGE_1Q,
        EXTRA_SYM_KEY,
        INVALID

    }
    enum OTR_SMP_STATE
    {
        EXPECT_1,
        EXPECT_2,
        EXPECT_3,
        EXPECT_4,
        INVALID


    }
   
     enum OTR_VERSION
    {
      // VERSION_1,
      // VERSION_1_2,
       VERSION_2,
       VERSION_3,
       //VERSION_2_AND_3,
      // 1_AND_2,
       INVALID
    }

  
    #endregion


    #region Classes
    class DHKeyPair
    {
        BigInteger _private_key = 0;
        BigInteger _public_key = 0;
        UInt32 _key_id = 0;
        byte[] _public_key_mpi_byte_array = null;

        public DHKeyPair(UInt32 key_id)
        {
            if (key_id < 0)
                throw new ArgumentException("DHKeyPair: DH Key ID value cannot be less than 1");

            _key_id = key_id;

        }
        public DHKeyPair()
        {


        }

        public DHKeyPair(BigInteger private_key, BigInteger public_key, UInt32 key_id)
        {

            if (private_key < 1)
                throw new ArgumentException("DHKeyPair: Private key value cannot be less than 0");


            if (public_key < 1)
                throw new ArgumentException("DHKeyPair: Public key value cannot be less than 0");

            if (key_id < 1)
                throw new ArgumentException("DHKeyPair: DH Key ID value cannot be less than 1");

            _key_id = key_id;
            _private_key = private_key;
            _public_key = public_key;


        }

        public void SetPublicKey(BigInteger public_key)
        {
            if (public_key < 0)
             throw new ArgumentException("SetPublicKey: Private key value cannot be less than 0");

            _public_key = public_key;



        }

        public void SetPrivateKey(BigInteger private_key)
        {
            if (private_key < 0)
            throw new ArgumentException("SetPrivateKey: Private key value cannot be less than 0");

            _private_key = private_key;



        }

        public BigInteger GetPublicKey()
        {
            return _public_key;

        }


        public BigInteger GetPrivateKey()
        {
            return _private_key;

        }
            

        public byte[] GetPrivateKeyBytes()
        {
            if (_private_key < 0)
            throw new ArgumentException("GetPrivateKeyBytes: Private key value cannot be less than 0. SetPrivateKey()");

            return _private_key.ToByteArray();
        }

        public byte[] GetPublicKeyMpiBytes()
        {
            if (_public_key < 0)
            throw new InvalidDataException("GetPublicKeyMpiBytes: The public key (BigInteger) cannot be less than 0. Call SetPublicKey()");

            if (_public_key_mpi_byte_array == null)
            Utility.EncodeMpiBytes(_public_key, ref _public_key_mpi_byte_array);

            return _public_key_mpi_byte_array;
        }

        public UInt32 GetKeyID()
        {
            return _key_id;

        }

        public byte[] GetKeyIDBytes()
        {

            return BitConverter.GetBytes(_key_id);

        }

        public byte[] GetDHPublicKeyData(byte[] key, UInt64 counter)
        {

          byte [] _encrypted_key = GetEncryptedPublicKey(key,counter);
          byte[] _hashed_key     = GetHashedPublicKey();

          byte[] _encoded_encrypted_key = null;
          byte[] _encoded_hashed_key = null;

          Utility.EncodeOTRDataBE(_encrypted_key, ref _encoded_encrypted_key);
          Utility.EncodeOTRDataBE(_hashed_key, ref _encoded_hashed_key);


                    
            
         byte[] _encoded_encrypted_hashed_key = new byte[_encoded_hashed_key.Length + _encoded_encrypted_key.Length];

         
          Buffer.BlockCopy(_encoded_encrypted_key, 0, _encoded_encrypted_hashed_key, 0, _encoded_encrypted_key.Length);
          Buffer.BlockCopy(_encoded_hashed_key, 0, _encoded_encrypted_hashed_key, _encoded_encrypted_key.Length, _encoded_hashed_key.Length);

         
          return _encoded_encrypted_hashed_key;

        }


        //Make these private 
        private byte[] GetEncryptedPublicKey(byte[] key, UInt64 counter)
        {
            return Utility.AESGetEncrypt(key, GetPublicKeyMpiBytes(), counter);

        }
        public byte[] GetHashedPublicKey()
        {
                      
            return Utility.SHA256GetHash(GetPublicKeyMpiBytes());

        }
       

       
       

    }
    class SignatureData
    {
        byte[] _x_byte_array_data = null;
        byte[] _m_byte_array_data = null;



        public SignatureData(byte[] x_byte_array_data, byte[] m_byte_array_data)
        {
            if (x_byte_array_data == null || x_byte_array_data.Length < 1)
                throw new ArgumentException("SignatureData: x_byte_array_data to be hashed cannot be null/empty");


            if (m_byte_array_data == null || m_byte_array_data.Length < 1)
                throw new ArgumentException("SignatureData: m_byte_array_data to be hashed cannot be null/empty");


            _x_byte_array_data = new byte[x_byte_array_data.Length];
            _m_byte_array_data = new byte[m_byte_array_data.Length];

        }
        

        public byte[] GetXDataArray()
        {

            return _x_byte_array_data;

        }

        public byte[] GetMDataArray()
        {

            return _m_byte_array_data;

        }

    }
    class AKEKeys
    {

        private byte[] _session_id = null;
        private byte[] _aes_key_1 = null;
        private byte[] _aes_key_2 = null;
        private byte[] _mac_key_1 = null;
        private byte[] _mac_key_2 = null;
        private byte[] _mac_key_3 = null;
        private byte[] _mac_key_4 = null;
        private byte[] _sec_data_byte_array = null;


        public void SetSecData(byte[] sec_data_byte_array)
        {

            if (sec_data_byte_array == null || sec_data_byte_array.Length == 0)
                throw new ArgumentException("AKEKeys: Sec data cannot be null/empty");

            _sec_data_byte_array = new byte[sec_data_byte_array.Length];

            Buffer.BlockCopy(sec_data_byte_array, 0, _sec_data_byte_array, 0, _sec_data_byte_array.Length);


        }
        public void SetSessionID(byte[] session_id)
        {

            if (session_id == null || session_id.Length == 0)
                throw new ArgumentException("AKEKeys: Session ID cannot be null/empty");

            _session_id = new byte[session_id.Length];

            Buffer.BlockCopy(session_id, 0, _session_id, 0, _session_id.Length);


        }
        public void SetAESKey1(byte[] aes_key_1)
        {
            if (aes_key_1 == null || aes_key_1.Length == 0)
                throw new ArgumentException("AKEKeys: AKE AES Key 1 value cannot be null/empty");


            _aes_key_1 = new byte[aes_key_1.Length];
            Buffer.BlockCopy(aes_key_1, 0, _aes_key_1, 0, _aes_key_1.Length);

        }
        public void SetAESKey2(byte[] aes_key_2)
        {
            if (aes_key_2 == null || aes_key_2.Length == 0)
                throw new ArgumentException("AKEKeys: AKE AES Key 2 value cannot be null/empty");

            
            _aes_key_2 = new byte[aes_key_2.Length];
            Buffer.BlockCopy(aes_key_2, 0, _aes_key_2, 0, _aes_key_2.Length);
        }
        public void SetMACKey1(byte[] mac_key_1)
        {
            if (mac_key_1 == null || mac_key_1.Length == 0)
                throw new ArgumentException("AKEKeys: AKE MAC Key 1 value cannot be null/empty");


            _mac_key_1 = new byte[mac_key_1.Length];
            Buffer.BlockCopy(mac_key_1, 0, _mac_key_1, 0, _mac_key_1.Length);
        }
        public void SetMACKey2(byte[] mac_key_2)
        {

            if (mac_key_2 == null || mac_key_2.Length == 0)
                throw new ArgumentException("AKEKeys: AKE MAC Key 2 value cannot be null/empty");


            _mac_key_2 = new byte[mac_key_2.Length];
            Buffer.BlockCopy(mac_key_2, 0, _mac_key_2, 0, _mac_key_2.Length);
        }
        public void SetMACKey3(byte[] mac_key_3)
        {

            if (mac_key_3 == null || mac_key_3.Length == 0)
                throw new ArgumentException("AKEKeys: AKE MAC Key 3 value cannot be null/empty");



            _mac_key_3 = new byte[mac_key_3.Length];
            Buffer.BlockCopy(mac_key_3, 0, _mac_key_3, 0, _mac_key_3.Length);
        }
        public void SetMACKey4(byte[] mac_key_4)
        {

            if (mac_key_4 == null || mac_key_4.Length == 0)
                throw new ArgumentException("AKEKeys: AKE MAC Key 4 value cannot be null/empty");



            _mac_key_4 = new byte[mac_key_4.Length];
            Buffer.BlockCopy(mac_key_4, 0, _mac_key_4, 0, _mac_key_4.Length);
        }

        public byte[] GetSecData()
        {
            return _sec_data_byte_array;

        }
        public byte[] GetSessionID()
        {
            return _session_id;
        }
        public byte[] GetAESKey1()
        {
            return _aes_key_1;
        }
        public byte[] GetAESKey2()
        {
            return _aes_key_2;
        }
        public byte[] GetMACKey1()
        {
            return _mac_key_1;
        }
        public byte[] GetMACKey2()
        {
            return _mac_key_2;
        }
        public byte[] GetMACKey3()
        {
            return _mac_key_3;
        }
        public byte[] GetMACKey4()
        {
            return _mac_key_4;
        }



    }
    class DataExchangeKeys
    {
        private byte[] _aes_key_send = null;
        private byte[] _aes_key_recv = null;
        private byte[] _mac_key_send = null;
        private byte[] _mac_key_recv = null;


        private byte[] _aes_key_extra = null;

        private byte[] _sec_data_byte_array = null;

        private OTR_END_TYPE _end_type = OTR_END_TYPE.INVALID;


        public void SetSecData(byte[] sec_data_byte_array)
        {

            if (sec_data_byte_array == null || sec_data_byte_array.Length == 0)
                throw new ArgumentException("DataExchangeKeys: Sec data cannot be null/empty");

            _sec_data_byte_array = new byte[sec_data_byte_array.Length];

            Buffer.BlockCopy(sec_data_byte_array, 0, _sec_data_byte_array, 0, _sec_data_byte_array.Length);


        }
        public void SetAESKeySend(byte[] aes_key_send)
        {
            if (aes_key_send == null || aes_key_send.Length == 0)
                throw new ArgumentException("DataExchangeKeys: Sending AES Key value cannot be null/empty");


            _aes_key_send = new byte[aes_key_send.Length];
            Buffer.BlockCopy(aes_key_send, 0, _aes_key_send, 0, _aes_key_send.Length);

        }
        public void SetAESKeyRecv(byte[] aes_key_recv)
        {
            if (aes_key_recv == null || aes_key_recv.Length == 0)
                throw new ArgumentException("DataExchangeKeys:Receiving AES Key value cannot be null/empty");

            _aes_key_recv = new byte[aes_key_recv.Length];
            Buffer.BlockCopy(aes_key_recv, 0, _aes_key_recv, 0, _aes_key_recv.Length);

        }
        public void SetMACKeySend(byte[] mac_key_send)
        {
            if (mac_key_send == null || mac_key_send.Length == 0)
                throw new ArgumentException("DataExchangeKeys: Sending MAC Key value cannot be null/empty");

            _mac_key_send = new byte[mac_key_send.Length];
            Buffer.BlockCopy(mac_key_send, 0, _mac_key_send, 0, _mac_key_send.Length);
        }
        public void SetMACKeyRecv(byte[] mac_key_recv)
        {
            if (mac_key_recv == null || mac_key_recv.Length == 0)
                throw new ArgumentException("DataExchangeKeys: Receiving MAC Key value cannot be null/empty");

            _mac_key_recv = new byte[mac_key_recv.Length];
            Buffer.BlockCopy(mac_key_recv, 0, _mac_key_recv, 0, _mac_key_recv.Length);
        }

        public void SetAESKeyExtra(byte[] aes_key_extra)
        {
            if (aes_key_extra == null || aes_key_extra.Length == 0)
                throw new ArgumentException("DataExchangeKeys: Extra AES Key value cannot be null/empty");

            _aes_key_extra = new byte[aes_key_extra.Length];
            Buffer.BlockCopy(aes_key_extra, 0, _aes_key_extra, 0, _aes_key_extra.Length);

        }

        public void SetEndType(OTR_END_TYPE end_type)
        {
            if (end_type == OTR_END_TYPE.INVALID)
                throw new ArgumentException("DataExchangeKeys: The End type value is invalid");

            _end_type = end_type;

        }

        public byte[] GetSecData()
        {
            return _sec_data_byte_array;

        }
        public byte[] GetAESKeySend()
        {
            return _aes_key_send;
        }
        public byte[] GetAESKeyRecv()
        {
            return _aes_key_recv;
        }
        public byte[] GetMACKeySend()
        {
            return _mac_key_send;
        }
        public byte[] GetMACKeyRecv()
        {
            return _mac_key_recv;
        }
        public byte[] GetAESKeyExtra()
        {
            return _aes_key_extra;
        }


        public OTR_END_TYPE GetEndType()
        {
            return _end_type;

        }
    }

    class OTRMessage
    {

     private OTR_MESSAGE_TYPE _message_type        = OTR_MESSAGE_TYPE.INVALID;
     private OTR_VERSION _protocol_version         = OTR_VERSION.INVALID;
     private byte   _flags                        = 0;
     private UInt32     _send_instance_tag        = 0;
     private UInt32    _receiver_instance_tag   = 0;
     private byte[] _encrypted_message_data     = null;
     private byte[] _encrypted_g_x_mpi              = null;
     private byte[] _hashed_g_x_mpi                 = null;
     private byte[] _g_x_mpi                    = null;
     private byte[] _revealed_aes_key           = null;
     private byte[] _encoded_encrypted_signature = null;
     private byte[] _mac_d_signature             = null;
     private UInt32 _sender_key_id = 0;
     private UInt32 _recipient_key_id = 0;
     private byte[] _next_dh_mpi_public_key     = null;
     private byte[] _counter_top_half           = null;
     private byte[] _authentication_mac         = null;
     private byte[] _bytes_to_authenticate       = null;
     private byte[] _old_mac_keys               = null;


     public void SetMessageType(OTR_MESSAGE_TYPE message_type)
     {

         _message_type = message_type;

     }
     public OTR_MESSAGE_TYPE GetMessageType()
     {

        return _message_type;

     }

     public void SetProtocolVersion(OTR_VERSION protocol_version)
     {
         _protocol_version = protocol_version;
     }
     public OTR_VERSION GetProtocolVersion()
     {
        return _protocol_version;
     }

     public void SetFlags(byte flags)
     {
         _flags = flags;
     }
     public byte GetFlags()
     {
         return _flags;
     }

     public void SetSenderInstanceTag(byte [] send_instance_tag)
     {
         if (send_instance_tag == null || send_instance_tag.Length < 1)
          throw new ArgumentException("SetSenderInstanceTag: The Sender instance tag cannot be null/empty");
         
         _send_instance_tag = BitConverter.ToUInt32(send_instance_tag,0);

         if (_send_instance_tag < 4)
          throw new ArgumentException("SetSenderInstanceTag: The Sender instance tag cannot be less than 4");


         
     }
     public UInt32 GetSenderInstanceTag()
     {
         return _send_instance_tag;
     }

     public void SetReceiverInstanceTag(byte [] receiver_instance_tag)
     {

         if (receiver_instance_tag == null || receiver_instance_tag.Length < 1)
         throw new ArgumentException("SetReceiverInstanceTag: The Sender instance tag cannot be null/empty");

         _receiver_instance_tag = BitConverter.ToUInt32(receiver_instance_tag,0);
         
         if (_receiver_instance_tag < 4 && _receiver_instance_tag != 0)
         throw new ArgumentException("SetReceiverInstanceTag: The Receiver instance tag can only have a value greater than 3  or be 0");

         
     }
     public UInt32 GetReceiverInstanceTag()
     {
         return _receiver_instance_tag;
     }

     public void SetEncryptedData(byte[] encrypted_message_data)
     {
         if (encrypted_message_data == null || encrypted_message_data.Length < 1)
         throw new ArgumentException("SetEncryptedData: The encrypted message data cannot be null/empty");

         _encrypted_message_data = new byte[encrypted_message_data.Length];

         Buffer.BlockCopy(encrypted_message_data, 0, _encrypted_message_data, 0, encrypted_message_data.Length);

        
     }
     public byte [] GetEncryptedData()
     {

         return _encrypted_message_data;

     }


     public void SetEncryptedGxMpi(byte[] encrypted_g_x_mpi)
     {
         if (encrypted_g_x_mpi == null || encrypted_g_x_mpi.Length < 1)
          throw new ArgumentException("SetEncryptedGx: The encrypted public key (g^x mod p) cannot be null/empty");

         _encrypted_g_x_mpi = new byte[encrypted_g_x_mpi.Length];

         Buffer.BlockCopy(encrypted_g_x_mpi, 0, _encrypted_g_x_mpi, 0, encrypted_g_x_mpi.Length);


     }
     public byte[] GetEncryptedGxMpi()
     {

         return _encrypted_g_x_mpi;

     }

     public void SetHashedGxMpi(byte[] hashed_g_x_mpi)
     {
         if (hashed_g_x_mpi == null || hashed_g_x_mpi.Length < 1)
         throw new ArgumentException("SetHashedGx: The hashed public key (g^x mod p) cannot be null/empty");

         _hashed_g_x_mpi = new byte[hashed_g_x_mpi.Length];

         Buffer.BlockCopy(hashed_g_x_mpi, 0, _hashed_g_x_mpi, 0, hashed_g_x_mpi.Length);


     }
     public byte[] GetHashedGxMpi()
     {

         return _hashed_g_x_mpi;

     }


     public void SetGxMpi(byte[] g_x_mpi)
     {
         if (g_x_mpi == null || g_x_mpi.Length < 1)
         throw new ArgumentException("SetHashedGx: The MPI encoded public key (g^x mod p) cannot be null/empty");

         _g_x_mpi = new byte[g_x_mpi.Length];

         Buffer.BlockCopy(g_x_mpi, 0, _g_x_mpi, 0, g_x_mpi.Length);


     }
     public byte[] GetGxMpi()
     {

         return _g_x_mpi;

     }


     public void SetRevealedKey(byte[] revealed_aes_key)
     {
         if (revealed_aes_key == null || revealed_aes_key.Length < 1)
             throw new ArgumentException("SetRevealedKey: The revealed AES key cannot be null/empty");

         _revealed_aes_key = new byte[revealed_aes_key.Length];

         Buffer.BlockCopy(revealed_aes_key, 0, _revealed_aes_key, 0, revealed_aes_key.Length);


     }
     public byte[] GetRevealedKey()
     {

         return _revealed_aes_key;

     }

     public void SetEncodedEncryptedSignature(byte[] encoded_encrypted_signature)
     {
         if (encoded_encrypted_signature == null || encoded_encrypted_signature.Length < 1)
             throw new ArgumentException("SetEncodedEncryptedSignature: The encrypted signature cannot be null/empty");

         _encoded_encrypted_signature = new byte[encoded_encrypted_signature.Length];

         Buffer.BlockCopy(encoded_encrypted_signature, 0, _encoded_encrypted_signature, 0, encoded_encrypted_signature.Length);


     }
     public byte[] GetEncodedEncryptedSignature()
     {

         return _encoded_encrypted_signature;

     }

     public void SetMacDSignature(byte[] mac_d_signature)
     {
         if (mac_d_signature == null || mac_d_signature.Length < 1)
             throw new ArgumentException("SetMacdSignature: The MAC'd signature cannot be null/empty");

         _mac_d_signature = new byte[mac_d_signature.Length];

         Buffer.BlockCopy(mac_d_signature, 0, _mac_d_signature, 0, mac_d_signature.Length);


     }
     public byte[] GetMacDSignature()
     {

         return _mac_d_signature;

     }

     public void SetSenderKeyId(byte[] sender_key_id)
     {
         if (sender_key_id == null || sender_key_id.Length < 1)
             throw new ArgumentException("SetSenderKeyId: The sender key id cannot be null/empty");

         _sender_key_id = BitConverter.ToUInt32(sender_key_id,0);
         

        


     }
     public UInt32 GetSenderKeyId()
     {

         return _sender_key_id;

     }

     public void SetRecipientKeyId(byte[] recipient_key_id)
     {
         if (recipient_key_id == null || recipient_key_id.Length < 1)
             throw new ArgumentException("SetRecipientKeyId: The recipient key id cannot be null/empty");


         _recipient_key_id = BitConverter.ToUInt32(recipient_key_id,0);
         


         


     }
     public UInt32 GetRecipientKeyId()
     {

         return _recipient_key_id;

     }

     public void SetNextDHPublicKeyMpi(byte[] next_dh_mpi_public_key)
     {
         if (next_dh_mpi_public_key == null || next_dh_mpi_public_key.Length < 1)
          throw new ArgumentException("SetNextDHPublicKey: The next MPI encoded DH public key cannot be null/empty");

         _next_dh_mpi_public_key = new byte[next_dh_mpi_public_key.Length];

         Buffer.BlockCopy(next_dh_mpi_public_key, 0, _next_dh_mpi_public_key, 0, next_dh_mpi_public_key.Length);


     }
     public byte[] GetNextDHPublicKeyMpi()
     {

         return _next_dh_mpi_public_key;

     }


     public void SetCounterTopHalf(byte[] counter_top_half)
     {
         if (counter_top_half == null || counter_top_half.Length < 1)
             throw new ArgumentException("SetCounterTopHalf: The top half of the counter cannot be null/empty");


         _counter_top_half = new byte[counter_top_half.Length];
         Buffer.BlockCopy(counter_top_half, 0, _counter_top_half, 0, counter_top_half.Length); 
        

     }
     public byte [] GetCounterTopHalf()
     {

         return _counter_top_half;

     }


     public void SetAuthenticationMAC(byte[] authentication_mac)
     {
         if (authentication_mac == null || authentication_mac.Length < 1)
             throw new ArgumentException("SetAuthenticationMAC: The authentication mac byte array cannot be null/empty");

         _authentication_mac = new byte[authentication_mac.Length];

         Buffer.BlockCopy(authentication_mac, 0, _authentication_mac, 0, authentication_mac.Length);


     }
     public byte[] GetAuthenticationMAC()
     {

         return _authentication_mac;

     }

    public void SetBytesToAuthenticate(byte[] bytes_to_authenticate)
     {
         if (bytes_to_authenticate == null || bytes_to_authenticate.Length < 1)
             throw new ArgumentException("SetBytesToAuthenticate: The byte array to be authenticated cannot be null/empty");

         _bytes_to_authenticate = new byte[bytes_to_authenticate.Length];

         Buffer.BlockCopy(bytes_to_authenticate, 0, _bytes_to_authenticate, 0, bytes_to_authenticate.Length);


     }
    public byte[] GetBytesToAuthenticate()
     {

         return _bytes_to_authenticate;

     }
        
      
     public void SetOldMacKeys(byte[] old_mac_keys)
     {
         if (old_mac_keys == null || old_mac_keys.Length < 1)
         throw new ArgumentException("SetOldMacKeys: The old mac keys byte array cannot be null/empty");

         _old_mac_keys = new byte[old_mac_keys.Length];

         Buffer.BlockCopy(old_mac_keys, 0, _old_mac_keys, 0, old_mac_keys.Length);


     }
     public byte[] GetOldMacKeys()
     {

         return _old_mac_keys;

     }
    
    }

    #endregion




}
