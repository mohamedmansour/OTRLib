using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using System.IO;


//Source:http://www.massapi.com/source/lcrypto-j2me-126/src/org/bouncycastle/crypto/signers/DSASigner.java.html

namespace OTR.Utilities
{
    class DSASigner
    {



        DsaPublicKeyParameters _public_key_param = null;
        DsaPrivateKeyParameters _private_key_param = null;
        SecureRandom _secure_random;
        AsymmetricCipherKeyPair _key_pair;
        BigInteger _P;
        BigInteger _Q;
        BigInteger _G;
        BigInteger _Y;
        BigInteger _X;
        byte[] _encoded_public_key_mpi_bytes = null;
        byte[] _dsa_public_key_finger_print = null;


        /* See July 2003 DSA FIPS Specs. Section 4.2  */

        const int P_LENGTH_BITS_1 = 1024;
        const int P_LENGTH_BITS_2 = 2048;
        const int P_LENGTH_BITS_3 = 2048;
        const int P_LENGTH_BITS_4 = 3072;

        const int Q_LENGTH_BITS_1 = 160;
        const int Q_LENGTH_BITS_2 = 224;
        const int Q_LENGTH_BITS_3 = 256;
        const int Q_LENGTH_BITS_4 = 256;


       private static List<DSAPQLengthValues> _dsa_p_q_length_list = null;



        const int MAX_FAILURE_COUNT = 20;




        public DSASigner()
        {
            InitKey();

            SetPublicKeyEncodedMpi();

        }

        public DSASigner(OTR.Interface.DSAKeyParams dsa_key_hex_strings)
        {
            if (dsa_key_hex_strings == null)
            throw new ArgumentException("DSASigner: The DSA key hex string object cannot be null");

            try
            {
                SetKey(dsa_key_hex_strings.GetParamP(), dsa_key_hex_strings.GetParamQ(),
                    dsa_key_hex_strings.GetParamG(), dsa_key_hex_strings.GetParamX());

            }
            catch (Exception ex)
            {
                throw new ArgumentException("DSASigner(DSAKeyHexStrings)" + ex.ToString());

            }


        }

        private void SetKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x)
        {



            if (p == null)
                throw new ArgumentException("The DSA key parameter P cannot be null");

            if (q == null)
                throw new ArgumentException("The DSA key parameter Q cannot be null");

            if (g == null)
                throw new ArgumentException("The DSA key parameter G cannot be null");

            if (x == null)
                throw new ArgumentException("The DSA key parameter X cannot be null");

            


            _P = p;
            _Q = q;
            _G = g;
            _X = x;

            _Y = _G.ModPow(_X, _P);

            DsaParameters _dsa_param = new DsaParameters(_P, _Q, _G);
            DsaKeyParameters _dsa_key_params = new DsaKeyParameters(true, _dsa_param);
            _public_key_param = new DsaPublicKeyParameters(_Y, _dsa_param);
            _private_key_param = new DsaPrivateKeyParameters(_X, _dsa_param);



            SetPublicKeyEncodedMpi();


        }
        
        private void InitKey()
        {
            _secure_random = new SecureRandom();
            DsaParametersGenerator _dsa_param_gen = new DsaParametersGenerator();
            DsaKeyPairGenerator _dsa_key_pair_gen = new DsaKeyPairGenerator();
            _dsa_param_gen.Init(1024, 80, _secure_random);

            DsaKeyGenerationParameters _dsa_key_gen_params = new DsaKeyGenerationParameters(_secure_random, _dsa_param_gen.GenerateParameters());

            _dsa_key_pair_gen.Init(_dsa_key_gen_params);
            _key_pair = _dsa_key_pair_gen.GenerateKeyPair();

            
            _private_key_param = (DsaPrivateKeyParameters)_key_pair.Private;
            _public_key_param = (DsaPublicKeyParameters)_key_pair.Public;






        }


        public void GenerateSignature(byte[] data_to_sign_byte_array, ref byte[] r_byte_array, ref byte[] s_byte_array)
        {




            if (data_to_sign_byte_array == null || data_to_sign_byte_array.Length < 1)
                throw new ArgumentException("GenerateSignature: The data byte array to sign cannot be null/empty");


            if (_private_key_param == null)
                throw new ArgumentException("GenerateSignature: The DSA private key cannot be null");


            if (_secure_random == null)
                _secure_random = new SecureRandom();



            BigInteger _data_to_sign = null;
            DsaParameters _parameters = null;
            BigInteger _k;
            BigInteger _r;
            BigInteger _s;
            int _q_bit_length;
            bool _do_again = false;
            int _failure_count = 0;

            _parameters = _private_key_param.Parameters;
            _data_to_sign = new BigInteger(1, data_to_sign_byte_array);
            _q_bit_length = _parameters.Q.BitLength;



                       
            /*    */
           // if (IsValidPQLength(_parameters.P.BitLength, _parameters.Q.BitLength) == false)
            //throw new InvalidDataException("GenerateSignature: The Length of the DSA key P parameter does not correspond to that of the Q parameter");

            
            

            do
            {

                try
                {

                    do
                    {
                        _k = new BigInteger(1, _secure_random);

                    }
                    while (_k.CompareTo(_parameters.Q) >= 0);


                    _r = _parameters.G.ModPow(_k, _parameters.P).Mod(_parameters.Q);
                    _k = _k.ModInverse(_parameters.Q).Multiply(_data_to_sign.Add((_private_key_param).X.Multiply(_r)));
                    _s = _k.Mod(_parameters.Q);
                    r_byte_array = _r.ToByteArray();
                    s_byte_array = _s.ToByteArray();
                    _do_again = false;

                }


                catch (Exception)
                {
                    if (MAX_FAILURE_COUNT == _failure_count)
                   throw new InvalidDataException("GenerateSignature: Failed sign data after " + MAX_FAILURE_COUNT.ToString() + " tries.");
                    _do_again = true;
                    _failure_count++;


                }

            }
            while (_do_again == true);



            Utility.SetAsMinimalLengthBE(ref r_byte_array);
            Utility.SetAsMinimalLengthBE(ref s_byte_array);



            /*
            Console.WriteLine("Q Length {0} \n", _parameters.Q.BitLength/8);
            Console.WriteLine("R Length {0} \n", r_byte_array.Length);
            Console.WriteLine("S Length {0} \n", s_byte_array.Length);//*/



        }


        public static bool VerifySignature(DsaPublicKeyParameters public_key_param, byte[] data_to_sign_byte_array, byte[] r_byte_array, byte[] s_byte_array)
        {


            BigInteger _data_to_sign = new BigInteger(1, data_to_sign_byte_array);
            BigInteger _r = new BigInteger(1, r_byte_array);
            BigInteger _s = new BigInteger(1, s_byte_array);
            DsaParameters _parameters = public_key_param.Parameters;

            BigInteger zero = BigInteger.ValueOf(0);


            /*
            if (IsValidPQLength(_parameters.P.BitLength, _parameters.Q.BitLength) == false)
            throw new InvalidDataException("VerifySignature: The Length of the DSA key P parameter does not correspond to that of the Q parameter");
            */



            if (zero.CompareTo(_r) >= 0 || _parameters.Q.CompareTo(_r) <= 0)
                return false;

            if (zero.CompareTo(_s) >= 0 || _parameters.Q.CompareTo(_s) <= 0)
                return false;

            BigInteger _w = _s.ModInverse(_parameters.Q);
            BigInteger _u1 = _data_to_sign.Multiply(_w).Mod(_parameters.Q);
            BigInteger _u2 = _r.Multiply(_w).Mod(_parameters.Q);

            _u1 = _parameters.G.ModPow(_u1, _parameters.P);
            _u2 = public_key_param.Y.ModPow(_u2, _parameters.P);
            BigInteger _v = _u1.Multiply(_u2).Mod(_parameters.P).Mod(_parameters.Q);


            // Console.WriteLine("Size of Q:{0}   \n   Size of R:{1}   \n  Size of S:{2} ", _parameters.Q.BitLength/8, r_byte_array.Length, s_byte_array.Length);


            return _v.Equals(_r);
        }


        private void SetPublicKeyEncodedMpi()
        {
            byte[] _dsa_p_mpi = null;
            byte[] _dsa_q_mpi = null;
            byte[] _dsa_g_mpi = null;
            byte[] _dsa_y_mpi = null;


            if (_X == null)
                _X = _private_key_param.X;

            if (_P == null)
                _P = _public_key_param.Parameters.P;

            if (_Q == null)
                _Q = _public_key_param.Parameters.Q;

            if (_G == null)
                _G = _public_key_param.Parameters.G;

            if (_Y == null)
                _Y = _G.ModPow(_X, _P);





            Utility.EncodeMpiBytes(_P, ref _dsa_p_mpi);
            Utility.EncodeMpiBytes(_Q, ref _dsa_q_mpi);
            Utility.EncodeMpiBytes(_G, ref _dsa_g_mpi);
            Utility.EncodeMpiBytes(_Y, ref _dsa_y_mpi);


            byte[] _temp_buffer = new byte[_dsa_p_mpi.Length + _dsa_q_mpi.Length + _dsa_g_mpi.Length + _dsa_y_mpi.Length];

            Buffer.BlockCopy(_dsa_p_mpi, 0, _temp_buffer, 0, _dsa_p_mpi.Length);
            Buffer.BlockCopy(_dsa_q_mpi, 0, _temp_buffer, _dsa_p_mpi.Length, _dsa_q_mpi.Length);
            Buffer.BlockCopy(_dsa_g_mpi, 0, _temp_buffer, _dsa_p_mpi.Length + _dsa_q_mpi.Length, _dsa_g_mpi.Length);
            Buffer.BlockCopy(_dsa_y_mpi, 0, _temp_buffer, _dsa_p_mpi.Length + _dsa_q_mpi.Length + _dsa_g_mpi.Length, _dsa_y_mpi.Length);


            /* Finger print minus the leading 2 bytes of DSA type computed */
            _dsa_public_key_finger_print = Utility.SHA1GetHash(_temp_buffer);



            byte[] _encoded_dsa_type = null;
            Utility.EncodeOTRShort(BitConverter.GetBytes(OTRConstants.DSA_PUB_KEY_TYPE), ref _encoded_dsa_type);


            _encoded_public_key_mpi_bytes = new byte[_encoded_dsa_type.Length + _temp_buffer.Length];



            Buffer.BlockCopy(_encoded_dsa_type, 0, _encoded_public_key_mpi_bytes, 0, _encoded_dsa_type.Length);
            Buffer.BlockCopy(_temp_buffer, 0, _encoded_public_key_mpi_bytes, _encoded_dsa_type.Length, _temp_buffer.Length);




        }

        public byte[] GetPublicKeyEncodedMpi()
        {

            return _encoded_public_key_mpi_bytes;


        }

        public byte[] GetDSAPublicKeyFingerPrint()
        {
            return _dsa_public_key_finger_print;

        }

        public string GetDSAPublicKeyFingerPrintHex()
        {

            return Utility.ByteToHex(_dsa_public_key_finger_print);

        }
        public OTR.Interface.DSAKeyParams GetDSAKeyParameters()
        {
            return new Interface.DSAKeyParams(_P, _Q, _G, _X);

        }
                     
        private static void InitLengthList()
        {

            if (_dsa_p_q_length_list != null)
                return;
            _dsa_p_q_length_list = new List<DSAPQLengthValues>();

            DSAPQLengthValues _p_q_length_values = null;


            _p_q_length_values = new DSAPQLengthValues(P_LENGTH_BITS_1, Q_LENGTH_BITS_1);
            _dsa_p_q_length_list.Add(_p_q_length_values);


            _p_q_length_values = new DSAPQLengthValues(P_LENGTH_BITS_2, Q_LENGTH_BITS_2);
            _dsa_p_q_length_list.Add(_p_q_length_values);

            
            _p_q_length_values = new DSAPQLengthValues(P_LENGTH_BITS_3, Q_LENGTH_BITS_3);
            _dsa_p_q_length_list.Add(_p_q_length_values);


            _p_q_length_values = new DSAPQLengthValues(P_LENGTH_BITS_4, Q_LENGTH_BITS_4);
            _dsa_p_q_length_list.Add(_p_q_length_values);          



        }      
        private static bool IsValidPQLength(int p_length, int q_length)
        {
            InitLengthList();


            foreach (DSAPQLengthValues _p_q_length_values in _dsa_p_q_length_list)
            {

                if (p_length == _p_q_length_values._p_length && q_length == _p_q_length_values._q_length)
                return true;

            }



            return false;

        }

    }



    class DSAPQLengthValues
    {
        public int _p_length = 0;
        public int _q_length = 0;


        public DSAPQLengthValues(int p_length, int q_length)
        {
            _p_length = p_length;
            _q_length = q_length;


        }


    }

}
