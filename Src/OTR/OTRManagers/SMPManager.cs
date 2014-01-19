using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;



using OTR.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Digests;
using System.IO;

namespace OTR.Managers
{
    class SMPManager
    {

        OTR_SMP_STATE _smp_state = OTR_SMP_STATE.EXPECT_1;


        private const int MESSAGE_1_MPI_COUNT = 6;
        private const int MESSAGE_2_MPI_COUNT = 11;
        private const int MESSAGE_3_MPI_COUNT = 8;
        private const int MESSAGE_4_MPI_COUNT = 3;


       private BigInteger[] _smp_first_message_data = null;
       private BigInteger[] _smp_second_message_data = null;
       private BigInteger[] _smp_third_message_data = null;

        SMPSessionObject _session_object = null;
       
                
        BigInteger _smp_secret = null;
        BigInteger PRIME_MODULO = null;
        BigInteger PRIME_MODULO_MINUS_2 = null;
        BigInteger GENERATOR = null;
        BigInteger SM_MODULO = null;


        private bool _is_started = false;


        public SMPManager()
        {
                      
            

            string MODULUS = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1";
            MODULUS += "29024E088A67CC74020BBEA63B139B22514A08798E3404DD";
            MODULUS += "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245";
            MODULUS += "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED";
            MODULUS += "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D";
            MODULUS += "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F";
            MODULUS += "83655D23DCA3AD961C62F356208552BB9ED529077096966D";
            MODULUS += "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";


            string MODULO_MINUS_2 = "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1";
            MODULO_MINUS_2 += "29024E088A67CC74020BBEA63B139B22514A08798E3404DD";
            MODULO_MINUS_2 += "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245";
            MODULO_MINUS_2 += "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED";
            MODULO_MINUS_2 += "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D";
            MODULO_MINUS_2 += "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F";
            MODULO_MINUS_2 += "83655D23DCA3AD961C62F356208552BB9ED529077096966D";
            MODULO_MINUS_2 += "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFD";



            string MODULUS_ORDER_S = "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68";
            MODULUS_ORDER_S += "948127044533E63A0105DF531D89CD9128A5043CC71A026E";
            MODULUS_ORDER_S += "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122";
            MODULUS_ORDER_S += "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6";
            MODULUS_ORDER_S += "F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9E";
            MODULUS_ORDER_S += "E1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AF";
            MODULUS_ORDER_S += "C1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36";
            MODULUS_ORDER_S += "B3861AA7255E4C0278BA36046511B993FFFFFFFFFFFFFFFF";

            PRIME_MODULO = new Org.BouncyCastle.Math.BigInteger(MODULUS, 16);
            GENERATOR = Org.BouncyCastle.Math.BigInteger.ValueOf(2);
            SM_MODULO = new Org.BouncyCastle.Math.BigInteger(MODULUS_ORDER_S, 16);
            PRIME_MODULO_MINUS_2 = new Org.BouncyCastle.Math.BigInteger(MODULO_MINUS_2, 16);


          

            
        }

        public void SMPStart(BigInteger smp_secret)
        {
           // Console.WriteLine("SMP Started \n");
            _smp_secret = smp_secret;

            _is_started = true;


        }

        public void SMPStart(byte [] smp_secret)
        {
           
            if (smp_secret == null || smp_secret.Length < 1)
            throw new ArgumentException("SMPStart: The SMP secret byte array cannot be null/empty");

            _smp_secret = new BigInteger(1,smp_secret);


            _is_started = true;

            
        }

        public void SMPEnd()
        {

             ResetData();
            _smp_first_message_data = null;
            _smp_second_message_data = null;
            _smp_third_message_data = null;
             _session_object = null;
            _smp_secret = null;

           
        }

        public bool IsSMPStarted()
        {

            return _is_started;
        }
        
        #region Message Set functions

        private void SetFirstMessageData()
        {

            BigInteger _g_2a = null;
            BigInteger _c_2 =  null;
            BigInteger _d_2 =  null;

            BigInteger _g_3a = null;
            BigInteger _c_3 =  null;
            BigInteger _d_3 =  null;


            _smp_first_message_data = new BigInteger[MESSAGE_1_MPI_COUNT];

            _session_object = new SMPSessionObject();


            BigInteger _exp_1 = GetRandomBigInt();
            BigInteger _exp_2 = GetRandomBigInt();

            _session_object.EXP_1 = _exp_1;
            _session_object.EXP_2 = _exp_2;


            
            _g_2a = GENERATOR.ModPow(_exp_1, PRIME_MODULO);
            _g_3a = GENERATOR.ModPow(_exp_2, PRIME_MODULO);


                    


            GetZKProof(1, _exp_1, ref _c_2, ref _d_2);
            GetZKProof(2, _exp_2, ref _c_3, ref _d_3);



            _smp_first_message_data[0] = _g_2a;
            _smp_first_message_data[1] = _c_2;
            _smp_first_message_data[2] = _d_2;

            _smp_first_message_data[3] = _g_3a;
            _smp_first_message_data[4] = _c_3;
            _smp_first_message_data[5] = _d_3;


           

        



        }
        private void SetSecondMessageData()
        {


            BigInteger _g_2b = null;
            BigInteger _c_2 = null;
            BigInteger _d_2 = null;

            BigInteger _g_3b = null;
            BigInteger _c_3 = null;
            BigInteger _d_3 = null;


            BigInteger _p = null;
            BigInteger _q = null;

            BigInteger _c_p = null;
            BigInteger _d_5 = null;
            BigInteger _d_6 = null;



            BigInteger _exp_1 = GetRandomBigInt();
            BigInteger _exp_2 = GetRandomBigInt();

            _session_object = new SMPSessionObject();


            _session_object.EXP_1 = _exp_1;
            _session_object.EXP_2 = _exp_2;

            _session_object.G_3x = _smp_first_message_data[3];


            _g_2b = GENERATOR.ModPow(_exp_1, PRIME_MODULO);
            _g_3b = GENERATOR.ModPow(_exp_2, PRIME_MODULO);

           
            _session_object.G_2 = _smp_first_message_data[0].ModPow(_session_object.EXP_1, PRIME_MODULO);
            _session_object.G_3 = _smp_first_message_data[3].ModPow(_session_object.EXP_2, PRIME_MODULO);

           
            GetZKProof(3, _exp_1, ref _c_2, ref _d_2);
            GetZKProof(4, _exp_2, ref _c_3, ref _d_3);


            _smp_second_message_data = new BigInteger[MESSAGE_2_MPI_COUNT];

            _smp_second_message_data[0] = _g_2b;
            _smp_second_message_data[1] = _c_2;
            _smp_second_message_data[2] = _d_2;

            _smp_second_message_data[3] = _g_3b;
            _smp_second_message_data[4] = _c_3;
            _smp_second_message_data[5] = _d_3;


            BigInteger _r_4  = GetRandomBigInt();


           
            _p = _session_object.G_3.ModPow(_r_4, PRIME_MODULO);
           
            
            BigInteger _g_1_r4 = GENERATOR.ModPow(_r_4, PRIME_MODULO);
            BigInteger _g_2_y = _session_object.G_2.ModPow(_smp_secret, PRIME_MODULO);

            _q = _g_1_r4.Multiply(_g_2_y).Mod(PRIME_MODULO);


            _session_object.P = _p;
            _session_object.Q = _q;

                     


            _smp_second_message_data[6] = _p;
            _smp_second_message_data[7] = _q;

          
            GetZKProof(5, _r_4, ref _c_p, ref _d_5, ref _d_6);

            _smp_second_message_data[8] = _c_p;
            _smp_second_message_data[9] = _d_5;
            _smp_second_message_data[10] = _d_6;


            

            

        }
        private void SetThirdMessage()
        {
            _smp_third_message_data = new BigInteger[MESSAGE_3_MPI_COUNT];


           
            BigInteger _p = null;
            BigInteger _q = null;

            BigInteger _c_p = null;
            BigInteger _d_5 = null;
            BigInteger _d_6 = null;


           
            BigInteger _c_r = null;
            BigInteger _d_7 = null;


            BigInteger _r_4 = GetRandomBigInt();


            _p = _session_object.G_3.ModPow(_r_4, PRIME_MODULO);

            BigInteger _g_1_r4 = GENERATOR.ModPow(_r_4, PRIME_MODULO);
            BigInteger _g_2_x = _session_object.G_2.ModPow(_smp_secret, PRIME_MODULO);

            _q = _g_1_r4.Multiply(_g_2_x).Mod(PRIME_MODULO);


            GetZKProof(6, _r_4, ref _c_p, ref _d_5, ref _d_6);

            BigInteger _inverse = _smp_second_message_data[6].ModInverse(PRIME_MODULO);
            _session_object.Pa_Pb = _p.Multiply(_inverse).Mod(PRIME_MODULO);

            _inverse = _smp_second_message_data[7].ModInverse(PRIME_MODULO);
            _session_object.Qa_Qb = _q.Multiply(_inverse).Mod(PRIME_MODULO);

            _session_object.R = _session_object.Qa_Qb.ModPow(_session_object.EXP_2, PRIME_MODULO);
        

            _session_object.G_3x = _smp_second_message_data[3];


            GetZKProof(7, ref _c_r, ref _d_7);


            _smp_third_message_data[0] = _p;
            _smp_third_message_data[1] = _q;
            _smp_third_message_data[2] = _c_p;
            _smp_third_message_data[3] = _d_5;
            _smp_third_message_data[4] = _d_6;
            _smp_third_message_data[5] = _session_object.R;
            _smp_third_message_data[6] = _c_r;
            _smp_third_message_data[7] = _d_7; 






        }
        
        #endregion

        #region Message formating functions

        public byte[] FormatSMPMessage1()
        {
            SetFirstMessageData();

            if (_smp_first_message_data == null || _smp_first_message_data.Length < MESSAGE_1_MPI_COUNT)
            throw new InvalidDataException("FormatSMPMessage1:The SMP first message data cannot be null or have elements less than " + MESSAGE_1_MPI_COUNT.ToString());


            byte[] _temp_mpi_buff = null;
            byte[] _message_buff = null;
            byte[] _g_2_mpi = null;
            byte[] _c_2_mpi = null;
            byte[] _d_2_mpi = null;

            byte[] _g_3_mpi = null;
            byte[] _c_3_mpi = null;
            byte[] _d_3_mpi = null;



            int _buff_length = 0;
            int _next_index = 0;




            Utility.EncodeMpiBytes(_smp_first_message_data[0], ref _g_2_mpi);
            Utility.EncodeMpiBytes(_smp_first_message_data[1], ref _c_2_mpi);
            Utility.EncodeMpiBytes(_smp_first_message_data[2], ref _d_2_mpi);

            Utility.EncodeMpiBytes(_smp_first_message_data[3], ref _g_3_mpi);
            Utility.EncodeMpiBytes(_smp_first_message_data[4], ref _c_3_mpi);
            Utility.EncodeMpiBytes(_smp_first_message_data[5], ref _d_3_mpi);

            _buff_length = _g_2_mpi.Length + _c_2_mpi.Length + _d_2_mpi.Length;
            _buff_length += _g_3_mpi.Length + _c_3_mpi.Length + _d_3_mpi.Length;


            _temp_mpi_buff = new byte[_buff_length];


            Buffer.BlockCopy(_g_2_mpi, 0, _temp_mpi_buff, _next_index, _g_2_mpi.Length);
            _next_index += _g_2_mpi.Length;

            Buffer.BlockCopy(_c_2_mpi, 0, _temp_mpi_buff, _next_index, _c_2_mpi.Length);
            _next_index += _c_2_mpi.Length;

            Buffer.BlockCopy(_d_2_mpi, 0, _temp_mpi_buff, _next_index, _d_2_mpi.Length);
            _next_index += _d_2_mpi.Length;

            Buffer.BlockCopy(_g_3_mpi, 0, _temp_mpi_buff, _next_index, _g_3_mpi.Length);
            _next_index += _g_3_mpi.Length;

            Buffer.BlockCopy(_c_3_mpi, 0, _temp_mpi_buff, _next_index, _c_3_mpi.Length);
            _next_index += _c_3_mpi.Length;

            Buffer.BlockCopy(_d_3_mpi, 0, _temp_mpi_buff, _next_index, _d_3_mpi.Length);
            _next_index += _d_3_mpi.Length;


            Utility.EncodeTLVSMPMessage(OTR_TLV_TYPE.SMP_MESSAGE_1, MESSAGE_1_MPI_COUNT, _temp_mpi_buff, ref _message_buff);



            _smp_state = OTR_SMP_STATE.EXPECT_2;


            return _message_buff;

        }
        public byte[] FormatSMPMessage2()
        {
            SetSecondMessageData();


            if (_smp_second_message_data == null || _smp_second_message_data.Length < MESSAGE_2_MPI_COUNT)
            throw new InvalidDataException("FormatSMPMessage2:The SMP second message data cannot be null or have elements less than " + MESSAGE_2_MPI_COUNT.ToString());


            byte[] _temp_mpi_buff = null;
            byte[] _message_buff = null;

            byte[] _g_2_b_mpi = null;
            byte[] _c_2_mpi = null;
            byte[] _d_2_mpi = null;

            byte[] _g_3_b_mpi = null;
            byte[] _c_3_mpi = null;
            byte[] _d_3_mpi = null;


            byte[] _p_b_mpi = null;
            byte[] _q_b_mpi = null;
            byte[] _c_p_mpi = null;
            byte[] _d_5_mpi = null;
            byte[] _d_6_mpi = null;

            int _buff_length = 0;
            int _next_index = 0;


            Utility.EncodeMpiBytes(_smp_second_message_data[0], ref _g_2_b_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[1], ref _c_2_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[2], ref _d_2_mpi);


            Utility.EncodeMpiBytes(_smp_second_message_data[3], ref _g_3_b_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[4], ref _c_3_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[5], ref _d_3_mpi);


            Utility.EncodeMpiBytes(_smp_second_message_data[6], ref _p_b_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[7], ref _q_b_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[8], ref _c_p_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[9], ref _d_5_mpi);
            Utility.EncodeMpiBytes(_smp_second_message_data[10], ref _d_6_mpi);

            _buff_length = _g_2_b_mpi.Length + _c_2_mpi.Length + _d_2_mpi.Length;
            _buff_length += _g_3_b_mpi.Length + _c_3_mpi.Length + _d_3_mpi.Length;
            _buff_length += _p_b_mpi.Length + _q_b_mpi.Length + _c_p_mpi.Length;
            _buff_length += _d_5_mpi.Length + _d_6_mpi.Length;

            _temp_mpi_buff = new byte[_buff_length];


            Buffer.BlockCopy(_g_2_b_mpi, 0, _temp_mpi_buff, _next_index, _g_2_b_mpi.Length);
            _next_index += _g_2_b_mpi.Length;

            Buffer.BlockCopy(_c_2_mpi, 0, _temp_mpi_buff, _next_index, _c_2_mpi.Length);
            _next_index += _c_2_mpi.Length;


            Buffer.BlockCopy(_d_2_mpi, 0, _temp_mpi_buff, _next_index, _d_2_mpi.Length);
            _next_index += _d_2_mpi.Length;

            Buffer.BlockCopy(_g_3_b_mpi, 0, _temp_mpi_buff, _next_index, _g_3_b_mpi.Length);
            _next_index += _g_3_b_mpi.Length;

            Buffer.BlockCopy(_c_3_mpi, 0, _temp_mpi_buff, _next_index, _c_3_mpi.Length);
            _next_index += _c_3_mpi.Length;


            Buffer.BlockCopy(_d_3_mpi, 0, _temp_mpi_buff, _next_index, _d_3_mpi.Length);
            _next_index += _d_3_mpi.Length;


            Buffer.BlockCopy(_p_b_mpi, 0, _temp_mpi_buff, _next_index, _p_b_mpi.Length);
            _next_index += _p_b_mpi.Length;

            Buffer.BlockCopy(_q_b_mpi, 0, _temp_mpi_buff, _next_index, _q_b_mpi.Length);
            _next_index += _q_b_mpi.Length;

            Buffer.BlockCopy(_c_p_mpi, 0, _temp_mpi_buff, _next_index, _c_p_mpi.Length);
            _next_index += _c_p_mpi.Length;

            Buffer.BlockCopy(_d_5_mpi, 0, _temp_mpi_buff, _next_index, _d_5_mpi.Length);
            _next_index += _d_5_mpi.Length;

            Buffer.BlockCopy(_d_6_mpi, 0, _temp_mpi_buff, _next_index, _d_6_mpi.Length);
            _next_index += _d_6_mpi.Length;


            Utility.EncodeTLVSMPMessage(OTR_TLV_TYPE.SMP_MESSAGE_2, MESSAGE_2_MPI_COUNT, _temp_mpi_buff, ref _message_buff);



            return _message_buff;


        }
        public byte[] FormatSMPMessage3()
        {

            SetThirdMessage();
            
            if (_smp_third_message_data == null || _smp_third_message_data.Length < MESSAGE_3_MPI_COUNT)
             throw new InvalidDataException("FormatSMPMessage3:The SMP third message data cannot be null or have elements less than " + MESSAGE_3_MPI_COUNT.ToString());

           


           
            byte[] _message_buff = null;
            byte[] _temp_mpi_buff = null;

            byte[] _p_a_mpi = null;
            byte[] _q_a_mpi = null;
            byte[] _c_p_mpi = null;
            byte[] _d_5_mpi = null;
            byte[] _d_6_mpi = null;

            byte[] _r_a_mpi = null;
            byte[] _c_r_mpi = null;
            byte[] _d_7_mpi = null;

           

            int _buff_length = 0;
            int _next_index = 0;


            Utility.EncodeMpiBytes(_smp_third_message_data[0], ref _p_a_mpi);
            _buff_length += _p_a_mpi.Length;


            Utility.EncodeMpiBytes(_smp_third_message_data[1], ref _q_a_mpi);
            _buff_length += _q_a_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[2], ref _c_p_mpi);
            _buff_length += _c_p_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[3], ref _d_5_mpi);
            _buff_length += _d_5_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[4], ref _d_6_mpi);
            _buff_length += _d_6_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[5], ref _r_a_mpi);
            _buff_length += _r_a_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[6], ref _c_r_mpi);
            _buff_length += _c_r_mpi.Length;

            Utility.EncodeMpiBytes(_smp_third_message_data[7], ref _d_7_mpi);
            _buff_length += _d_7_mpi.Length;


            _temp_mpi_buff = new byte[_buff_length];


            Buffer.BlockCopy(_p_a_mpi, 0, _temp_mpi_buff, _next_index, _p_a_mpi.Length);
            _next_index += _p_a_mpi.Length;

            Buffer.BlockCopy(_q_a_mpi, 0, _temp_mpi_buff, _next_index, _q_a_mpi.Length);
            _next_index += _q_a_mpi.Length;

            Buffer.BlockCopy(_c_p_mpi, 0, _temp_mpi_buff, _next_index, _c_p_mpi.Length);
            _next_index += _c_p_mpi.Length;

            Buffer.BlockCopy(_d_5_mpi, 0, _temp_mpi_buff, _next_index, _d_5_mpi.Length);
            _next_index += _d_5_mpi.Length;

            Buffer.BlockCopy(_d_6_mpi, 0, _temp_mpi_buff, _next_index, _d_6_mpi.Length);
            _next_index += _d_6_mpi.Length;

            Buffer.BlockCopy(_r_a_mpi, 0, _temp_mpi_buff, _next_index, _r_a_mpi.Length);
            _next_index += _r_a_mpi.Length;

            Buffer.BlockCopy(_c_r_mpi, 0, _temp_mpi_buff, _next_index, _c_r_mpi.Length);
            _next_index += _c_r_mpi.Length;

            Buffer.BlockCopy(_d_7_mpi, 0, _temp_mpi_buff, _next_index, _d_7_mpi.Length);
            _next_index += _d_7_mpi.Length;


            Utility.EncodeTLVSMPMessage(OTR_TLV_TYPE.SMP_MESSAGE_3, MESSAGE_3_MPI_COUNT, _temp_mpi_buff, ref _message_buff);



            return _message_buff;

        }
        public byte[] FormatSMPMessage4()
        {
            

         BigInteger _r_b = _session_object.Qa_Qb.ModPow(_session_object.EXP_2, PRIME_MODULO);

        
         BigInteger c = null; 
         BigInteger d =null;

         GetZKProof(8, ref c, ref d);

         //Console.WriteLine("value: {0} \n", d);

         byte[] _message_buff = null;
         byte[] _temp_mpi_buff = null;

         byte[] _r_b_mpi = null;
         byte[] _c_mpi = null;
         byte[] _d_mpi = null;
         

         int _buff_length = 0;
         int _next_index = 0;

         Utility.EncodeMpiBytes(_r_b, ref _r_b_mpi);
         _buff_length += _r_b_mpi.Length;

         Utility.EncodeMpiBytes(c, ref _c_mpi);
         _buff_length += _c_mpi.Length;

         Utility.EncodeMpiBytes(d, ref _d_mpi);
         _buff_length += _d_mpi.Length;


         _temp_mpi_buff = new byte[_buff_length];

         Buffer.BlockCopy(_r_b_mpi, 0, _temp_mpi_buff, _next_index, _r_b_mpi.Length);
         _next_index += _r_b_mpi.Length;

         Buffer.BlockCopy(_c_mpi, 0, _temp_mpi_buff, _next_index, _c_mpi.Length);
         _next_index += _c_mpi.Length;

         Buffer.BlockCopy(_d_mpi, 0, _temp_mpi_buff, _next_index, _d_mpi.Length);

         Utility.EncodeTLVSMPMessage(OTR_TLV_TYPE.SMP_MESSAGE_4, MESSAGE_4_MPI_COUNT, _temp_mpi_buff, ref _message_buff);


            

          return _message_buff;
        }
        

        #endregion


        #region Message Processing functions


        public byte[] ProcessSMPMessage(byte[] smp_byte_array, OTR_TLV_TYPE tlv_type, ref OTR.Interface.OTR_SMP_EVENT smp_event_type_1, ref OTR.Interface.OTR_SMP_EVENT smp_event_type_2, ref string message)
        {

            try
            {
                if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_1)
                    return ProcessSMPMessage1(smp_byte_array, ref smp_event_type_1, ref message);

                else if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_2)
                 return ProcessSMPMessage2(smp_byte_array, ref smp_event_type_1, ref message);

                else if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_3)
                    return ProcessSMPMessage3(smp_byte_array, ref smp_event_type_1, ref smp_event_type_2, ref message);


                else if (tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_4)
                    return ProcessSMPMessage4(smp_byte_array, ref smp_event_type_1, ref message);
            }
            catch (Exception ex)
            {
                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage:" + ex.ToString();
                ResetData();
                //TODO(mo)
                //Console.WriteLine("Exception {0} \n", ex.ToString());
            }
            

            return null;
        }

        private byte[] ProcessSMPMessage1(byte[] smp_byte_array, ref OTR.Interface.OTR_SMP_EVENT smp_event_type, ref string message)
        {

            if (smp_byte_array == null || smp_byte_array.Length < 1)
            {


                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
               message = "ProcessSMPMessage1: The SMP byte array cannot be null/empty";
               ResetData();
               return null;
                
            }


            if (_smp_state != OTR_SMP_STATE.EXPECT_1)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage1: Illigal state";
                ResetData();

                return null;

            }


            int _start_index = 0;
            uint _mpi_count = 0;
            byte[] _mpis_buffer = null;

            byte[] _g_2_mpi = null;
            byte[] _c_2_mpi = null;
            byte[] _d_2_mpi = null;

            byte[] _g_3_mpi = null;
            byte[] _c_3_mpi = null;
            byte[] _d_3_mpi = null;


            Utility.DecodeTLVSMPMessage(smp_byte_array, _start_index, ref _mpi_count, ref _mpis_buffer);


            if (_mpi_count != MESSAGE_1_MPI_COUNT)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage1: The MPI count must be " + MESSAGE_1_MPI_COUNT.ToString();
                ResetData();

                return null;
            }



            _start_index = 0;



            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _g_2_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_2_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_2_mpi);

            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _g_3_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_3_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_3_mpi);


            _smp_first_message_data = new BigInteger[_mpi_count];


            Utility.DecodeMpiFromBytes(_g_2_mpi, 0, ref _smp_first_message_data[0]);
            Utility.DecodeMpiFromBytes(_c_2_mpi, 0, ref _smp_first_message_data[1]);
            Utility.DecodeMpiFromBytes(_d_2_mpi, 0, ref _smp_first_message_data[2]);


            Utility.DecodeMpiFromBytes(_g_3_mpi, 0, ref _smp_first_message_data[3]);
            Utility.DecodeMpiFromBytes(_c_3_mpi, 0, ref _smp_first_message_data[4]);
            Utility.DecodeMpiFromBytes(_d_3_mpi, 0, ref _smp_first_message_data[5]);


           
            if (IsValidValue(_smp_first_message_data[0]) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage1: G2a is not valid";
                ResetData();

                return null;
            }

            if (IsValidValue(_smp_first_message_data[3]) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: G3a is not valid";
                ResetData();
                return null;
            }



            if (VerifyZKProof(1, _smp_first_message_data[0], _smp_first_message_data[1], _smp_first_message_data[2]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage1: Zero-Knowledge Proof (Prefix 1) failed";
                ResetData();

                return null;
            }

            if (VerifyZKProof(2, _smp_first_message_data[3], _smp_first_message_data[4], _smp_first_message_data[5]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage1: Zero-Knowledge Proof (Prefix 2) failed";
                ResetData();

                return null;
            }


           

           

            _smp_state = OTR_SMP_STATE.EXPECT_3;


            smp_event_type = OTR.Interface.OTR_SMP_EVENT.SEND;


            return FormatSMPMessage2();

        }
        private byte[] ProcessSMPMessage2(byte[] smp_byte_array, ref OTR.Interface.OTR_SMP_EVENT smp_event_type, ref string message)
        {
            if (_smp_state != OTR_SMP_STATE.EXPECT_2)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: The SMP byte array cannot be null/empty";
                ResetData();

                return null;

            }


            int _start_index = 0;
            uint _mpi_count = 0;
            byte[] _mpis_buffer = null;


            Utility.DecodeTLVSMPMessage(smp_byte_array, _start_index, ref _mpi_count, ref _mpis_buffer);


            if (_mpi_count != MESSAGE_2_MPI_COUNT)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: The MPI count must be " + MESSAGE_2_MPI_COUNT.ToString();
                ResetData();
                return null;

            }

            byte[] _g_2_b_mpi = null;
            byte[] _c_2_mpi = null;
            byte[] _d_2_mpi = null;

            byte[] _g_3_b_mpi = null;
            byte[] _c_3_mpi = null;
            byte[] _d_3_mpi = null;


            byte[] _p_b_mpi = null;
            byte[] _q_b_mpi = null;
            byte[] _c_p_mpi = null;
            byte[] _d_5_mpi = null;
            byte[] _d_6_mpi = null;



            _start_index = 0;



            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _g_2_b_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_2_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_2_mpi);


            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _g_3_b_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_3_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_3_mpi);


            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _p_b_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _q_b_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_p_mpi);


            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_5_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_6_mpi);

            _smp_second_message_data = new BigInteger[_mpi_count];

            Utility.DecodeMpiFromBytes(_g_2_b_mpi, 0, ref  _smp_second_message_data[0]);
            Utility.DecodeMpiFromBytes(_c_2_mpi, 0, ref  _smp_second_message_data[1]);
            Utility.DecodeMpiFromBytes(_d_2_mpi, 0, ref  _smp_second_message_data[2]);


            Utility.DecodeMpiFromBytes(_g_3_b_mpi, 0, ref  _smp_second_message_data[3]);
            Utility.DecodeMpiFromBytes(_c_3_mpi, 0, ref  _smp_second_message_data[4]);
            Utility.DecodeMpiFromBytes(_d_3_mpi, 0, ref  _smp_second_message_data[5]);


            Utility.DecodeMpiFromBytes(_p_b_mpi, 0, ref  _smp_second_message_data[6]);
            Utility.DecodeMpiFromBytes(_q_b_mpi, 0, ref  _smp_second_message_data[7]);
            Utility.DecodeMpiFromBytes(_c_p_mpi, 0, ref  _smp_second_message_data[8]);

            Utility.DecodeMpiFromBytes(_d_5_mpi, 0, ref  _smp_second_message_data[9]);
            Utility.DecodeMpiFromBytes(_d_6_mpi, 0, ref  _smp_second_message_data[10]);





            if (IsValidValue(_smp_second_message_data[0]) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: G2b is not valid";
                ResetData();

                return null;
            }

            if (IsValidValue(_smp_second_message_data[3]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: G3b is not valid";
                ResetData();

                return null;
            }

            if (IsValidValue(_smp_second_message_data[6]) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: P is not valid";
                ResetData();

                return null;
            }

            if (IsValidValue(_smp_second_message_data[7]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: Q is not valid";
                ResetData();

                return null;
            }



            _session_object.G_2 = _smp_second_message_data[0].ModPow(_session_object.EXP_1, PRIME_MODULO);
            _session_object.G_3 = _smp_second_message_data[3].ModPow(_session_object.EXP_2, PRIME_MODULO);




            if (VerifyZKProof(3, _smp_second_message_data[0], _smp_second_message_data[1], _smp_second_message_data[2]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: Zero-Knowledge Proof (Prefix 3) failed";
                ResetData();


                return null;
            }


            if (VerifyZKProof(4, _smp_second_message_data[3], _smp_second_message_data[4], _smp_second_message_data[5]) == false)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: Zero-Knowledge Proof (Prefix 4) failed";
                ResetData();

                return null;
            }



            if (VerifyZKProof(5, _smp_second_message_data[6], _smp_second_message_data[7],
                _smp_second_message_data[8], _smp_second_message_data[9],
                _smp_second_message_data[10]) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage2: Zero-Knowledge Proof (Prefix 5) failed";
                ResetData();

                return null;

            }




            _smp_state = OTR_SMP_STATE.EXPECT_4;

            smp_event_type = OTR.Interface.OTR_SMP_EVENT.SEND;



            return FormatSMPMessage3();
        }
        private byte[] ProcessSMPMessage3(byte[] smp_byte_array, ref OTR.Interface.OTR_SMP_EVENT smp_event_type_1, ref OTR.Interface.OTR_SMP_EVENT smp_event_type_2, ref string message)
        {

            if (smp_byte_array == null || smp_byte_array.Length < 1)
            {

                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: The SMP byte array cannot be null/empty";
                ResetData();

                return null;  
            }

            
            
            if (_smp_state != OTR_SMP_STATE.EXPECT_3)
            {
                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: Illigal state";
                ResetData();

                return null;

            }

            int _start_index = 0;
            uint _mpi_count = 0;
            byte[] _mpis_buffer = null;



            Utility.DecodeTLVSMPMessage(smp_byte_array, _start_index, ref _mpi_count, ref _mpis_buffer);


            if (_mpi_count != MESSAGE_3_MPI_COUNT)
            {

                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3:The MPI count must be " + MESSAGE_3_MPI_COUNT.ToString();
                ResetData();

                return null;
            }


                      


            byte[] _p_a_mpi = null;
            byte[] _q_a_mpi = null;
            byte[] _c_p_mpi = null;
            byte[] _d_5_mpi = null;
            byte[] _d_6_mpi = null;

            byte[] _r_a_mpi = null;
            byte[] _c_r_mpi = null;
            byte[] _d_7_mpi = null;

            _start_index = 0;


            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _p_a_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _q_a_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_p_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_5_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_6_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _r_a_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_r_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_7_mpi);


            _smp_third_message_data = new BigInteger[_mpi_count];


            Utility.DecodeMpiFromBytes(_p_a_mpi, 0, ref  _smp_third_message_data[0]);
            Utility.DecodeMpiFromBytes(_q_a_mpi, 0, ref  _smp_third_message_data[1]);
            Utility.DecodeMpiFromBytes(_c_p_mpi, 0, ref  _smp_third_message_data[2]);
            Utility.DecodeMpiFromBytes(_d_5_mpi, 0, ref  _smp_third_message_data[3]);
            Utility.DecodeMpiFromBytes(_d_6_mpi, 0, ref  _smp_third_message_data[4]);
            Utility.DecodeMpiFromBytes(_r_a_mpi, 0, ref  _smp_third_message_data[5]);
            Utility.DecodeMpiFromBytes(_c_r_mpi, 0, ref  _smp_third_message_data[6]);
            Utility.DecodeMpiFromBytes(_d_7_mpi, 0, ref  _smp_third_message_data[7]);



            if (IsValidValue(_smp_third_message_data[0]) == false)
            {


                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: Pa is not valid";
                ResetData();


                return null;
            }

            if (IsValidValue(_smp_third_message_data[1]) == false)
            {
                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: Qa is not valid";
                ResetData();

                return null;
            }

            if (IsValidValue(_smp_third_message_data[5]) == false)
            {
                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: Ra is not valid";
                ResetData();

                return null;
            }


            if (VerifyZKProof(6, _smp_third_message_data[0], _smp_third_message_data[1],
               _smp_third_message_data[2], _smp_third_message_data[3],
               _smp_third_message_data[4]) == false)
            {

                smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage3: Zero-Knowledge Proof (Prefix 6) failed";
                ResetData();

                return null;

            }


            BigInteger _inverse = _session_object.Q.ModInverse(PRIME_MODULO);
            _session_object.Qa_Qb = _smp_third_message_data[1].Multiply(_inverse).Mod(PRIME_MODULO);


            _inverse = _session_object.P.ModInverse(PRIME_MODULO);
            _session_object.Pa_Pb = _smp_third_message_data[0].Multiply(_inverse).Mod(PRIME_MODULO);

            
            if (VerifyZKProofA(7,_smp_third_message_data[5],
              _smp_third_message_data[6], _smp_third_message_data[7]) == false)
          {
              smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.ABORT;
              message = "ProcessSMPMessage3: Zero-Knowledge Proof (Prefix 7) failed";
              ResetData();
              return null;

          }
         


           BigInteger _r_ab = _smp_third_message_data[5].ModPow(_session_object.EXP_2, PRIME_MODULO);


             _smp_state = OTR_SMP_STATE.EXPECT_1;

           

            if (_r_ab.Equals(_session_object.Pa_Pb) == true)
            {
                smp_event_type_2 = OTR.Interface.OTR_SMP_EVENT.SUCCEEDED;
               // Console.WriteLine("SMP completed succesfully \n");
                message = "ProcessSMPMessage3: SMP completed succesfully";
                ResetData();
                

            }
            else
            {

                smp_event_type_2 = OTR.Interface.OTR_SMP_EVENT.FAILED;
               // Console.WriteLine("SMP Man in the middle suspected  \n");
                message = "ProcessSMPMessage3: SMP Man in the middle suspected";
                ResetData();
                

            }



            smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.SEND;


           

           return FormatSMPMessage4();

           


            
        }
        private byte[] ProcessSMPMessage4(byte[] smp_byte_array, ref OTR.Interface.OTR_SMP_EVENT smp_event_type, ref string message)
        {
            

            if (smp_byte_array == null || smp_byte_array.Length < 1)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage4: The SMP byte array cannot be null/empty";
                ResetData();

                          
                return null;
            }
            
            
            
            if (_smp_state != OTR_SMP_STATE.EXPECT_4)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage4: Illigal state";
                ResetData();

                
 
                return null;

            }


            int _start_index = 0;
            uint _mpi_count = 0;
            byte[] _mpis_buffer = null;


            Utility.DecodeTLVSMPMessage(smp_byte_array, _start_index, ref _mpi_count, ref _mpis_buffer);

            if (_mpi_count != MESSAGE_4_MPI_COUNT)
            {


                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage4: The MPI count must be " + MESSAGE_4_MPI_COUNT.ToString();
                ResetData();

                return null;
            }

            byte[] _r_b_mpi = null;
            byte[] _c_mpi = null;
            byte[] _d_mpi = null;

            BigInteger _r_b = null;
            BigInteger _c = null;
            BigInteger _d = null;

            _start_index = 0;

            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _r_b_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _c_mpi);
            _start_index = Utility.DecoupleMpiFromBytes(_mpis_buffer, _start_index, ref _d_mpi);

            Utility.DecodeMpiFromBytes(_r_b_mpi, 0, ref _r_b);
            Utility.DecodeMpiFromBytes(_c_mpi, 0, ref  _c);
            Utility.DecodeMpiFromBytes(_d_mpi, 0, ref  _d);

            if (IsValidValue(_r_b) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage4: Rb is not valid";
                ResetData();

                return null;
            }


  


            if (VerifyZKProofA(8, _r_b,_c, _d) == false)
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.ABORT;
                message = "ProcessSMPMessage4: Zero-Knowledge Proof (Prefix 8) failed";
                ResetData();

                return null;
            }


            _smp_state = OTR_SMP_STATE.EXPECT_1;


            BigInteger _r_ab = _r_b.ModPow(_session_object.EXP_2, PRIME_MODULO);

            
            if (_r_ab.Equals(_session_object.Pa_Pb) == true)
            {
                smp_event_type = OTR.Interface.OTR_SMP_EVENT.SUCCEEDED;
               // Console.WriteLine("SMP completed succesfully \n");
                message = "ProcessSMPMessage4: SMP completed succesfully";
                ResetData();
                

            }
            else
            {

                smp_event_type = OTR.Interface.OTR_SMP_EVENT.FAILED;
              //  Console.WriteLine("SMP Man in the middle suspected  \n");
                message = "ProcessSMPMessage4: SMP Man in the middle suspected";
                ResetData();


            }


            return null;

            

            
        }
       
       
       #endregion

                
        #region Zero Knowledge Proof functions


        private void GetZKProof(byte hash_number, BigInteger exp, ref BigInteger c, ref BigInteger d)
        {
            BigInteger _r = GetRandomBigInt();
            BigInteger _temp = GENERATOR.ModPow(_r, PRIME_MODULO);
            
            
            c = SMPHash(hash_number, _temp, null);


            _temp = exp.Multiply(c).Mod(SM_MODULO);

            d = _r.Subtract(_temp).Mod(SM_MODULO);

                    

        }

        private void GetZKProof(byte hash_number, BigInteger r, ref BigInteger c, ref BigInteger d_1, ref BigInteger d_2)
        {


            BigInteger _r_1 = GetRandomBigInt();
            BigInteger _r_2 = GetRandomBigInt();

          

            BigInteger _temp = GENERATOR.ModPow(_r_1, PRIME_MODULO);
            BigInteger _temp_2 = _session_object.G_2.ModPow(_r_2, PRIME_MODULO);
            _temp_2 = _temp.Multiply(_temp_2).Mod(PRIME_MODULO);
            _temp = _session_object.G_3.ModPow(_r_1, PRIME_MODULO);


            c = SMPHash(hash_number, _temp, _temp_2);

            _temp = r.Multiply(c).Mod(SM_MODULO);
            d_1 = _r_1.Subtract(_temp).Mod(SM_MODULO);

            _temp = _smp_secret.Multiply(c).Mod(SM_MODULO);
            d_2 = _r_2.Subtract(_temp).Mod(SM_MODULO);

             


        }

        private void GetZKProof(byte hash_number, ref BigInteger c, ref BigInteger d)
        {
            BigInteger _r_1 = GetRandomBigInt();

            BigInteger _g1_r1 = GENERATOR.ModPow(_r_1, PRIME_MODULO);

            BigInteger _q1_q2_r1 = _session_object.Qa_Qb.ModPow(_r_1, PRIME_MODULO);


            c = SMPHash(hash_number, _g1_r1, _q1_q2_r1);

            BigInteger _temp = _session_object.EXP_2.Multiply(c).Mod(SM_MODULO);
            d = _r_1.Subtract(_temp).Mod(SM_MODULO);

          

        }
              

        private bool VerifyZKProof(byte hash_number, BigInteger g, BigInteger c, BigInteger d)
        {
            BigInteger _g_d = GENERATOR.ModPow(d, PRIME_MODULO);
            BigInteger _x_c = g.ModPow(c, PRIME_MODULO);
            BigInteger _gd_xc = _g_d.Multiply(_x_c).Mod(PRIME_MODULO);


            BigInteger _computed_hashed_c = SMPHash(hash_number, _gd_xc, null);


            
            return _computed_hashed_c.Equals(c);

        }

        private bool VerifyZKProof(byte hash_number, BigInteger p,BigInteger q, BigInteger c, BigInteger d_1, BigInteger d_2)
        {

                       
            BigInteger _temp_1 = _session_object.G_3.ModPow(d_1,PRIME_MODULO);
            BigInteger _temp_2 = p.ModPow(c,PRIME_MODULO);
            _temp_1 = _temp_2.Multiply(_temp_1).Mod(PRIME_MODULO);

            _temp_2 = GENERATOR.ModPow(d_1,PRIME_MODULO);
            BigInteger _temp_3 = _session_object.G_2.ModPow(d_2,PRIME_MODULO);
            _temp_2 = _temp_2.Multiply(_temp_3).Mod(PRIME_MODULO);
            _temp_3 = q.ModPow(c,PRIME_MODULO);
            _temp_2 =  _temp_3.Multiply(_temp_2).Mod(PRIME_MODULO);

            
            BigInteger _computed_hashed_c = SMPHash(hash_number, _temp_1, _temp_2);

                     
            
            return _computed_hashed_c.Equals(c);

        }

        private bool VerifyZKProofA(byte hash_number, BigInteger r, BigInteger c, BigInteger d)
        {
            BigInteger _temp_2 = GENERATOR.ModPow(d, PRIME_MODULO);
            BigInteger _temp_3 = _session_object.G_3x.ModPow(c, PRIME_MODULO);
            BigInteger _temp_1 = _temp_2.Multiply(_temp_3).Mod(PRIME_MODULO);

                      
                        
           
            _temp_3 = _session_object.Qa_Qb.ModPow(d, PRIME_MODULO);
            _temp_2 = r.ModPow(c, PRIME_MODULO);
            _temp_2 = _temp_3.Multiply(_temp_2).Mod(PRIME_MODULO);

             BigInteger _computed_hashed_c = SMPHash(hash_number, _temp_1, _temp_2);

                         


            return _computed_hashed_c.Equals(c);

        }
        #endregion


        #region Utility functions
                    
        private void ResetData()
        {
          
           _smp_state = OTR_SMP_STATE.EXPECT_1;
           _is_started = false;

        }

              

        private BigInteger SMPHash(byte hash_number, BigInteger big_int_a, BigInteger big_int_b)
        {

            byte[] _encoded_mpi = null;



            Sha256Digest _sha256 = new Sha256Digest();


            _sha256.Update(hash_number);

            Utility.EncodeMpiBytes(big_int_a, ref _encoded_mpi);
            _sha256.BlockUpdate(_encoded_mpi, 0, _encoded_mpi.Length);


            if (big_int_b != null)
            {

                Utility.EncodeMpiBytes(big_int_b, ref _encoded_mpi);
                _sha256.BlockUpdate(_encoded_mpi, 0, _encoded_mpi.Length);
            }



            byte[] _hashed_bytes = new byte[_sha256.GetDigestSize()];

            _sha256.DoFinal(_hashed_bytes, 0);

          


            return new BigInteger(1,_hashed_bytes);

            
           

        }
        
        
        public static BigInteger GetRandomBigInt()
        {

            byte[] _random_bytes = Utility.GetRandomByteArray(OTRConstants.SMP_RAND_EXP_LENGTH_BYTES);


            return new BigInteger(1, _random_bytes);

        }

        private bool IsValidValue(BigInteger big_int_value)
        {
            if (big_int_value.CompareTo(GENERATOR) > 0 && big_int_value.CompareTo(PRIME_MODULO_MINUS_2) <= 0)
            return true;


            return false;
       }

        #endregion

       
    
    
    }

    class SMPSessionObject
    {
        public BigInteger EXP_1;
        public BigInteger EXP_2;
        public BigInteger G_2;
        public BigInteger G_3;
        public BigInteger P;
        public BigInteger Q;
        public BigInteger R;
        public BigInteger G_3x;
        public BigInteger Qa_Qb;
        public BigInteger Pa_Pb;
       

    }

   
}
