using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Numerics;
using System.Threading;


using OTR.Interface;
using OTR.Utilities;
using System.Diagnostics;




namespace OTR.Managers
{
     class OTRSession
    {

        #region   Varaibles

        OTR_VERSION _current_otr_version = OTR_VERSION.INVALID;


        OTRMessage _otr_message = null;
        OTR.Interface.OTREventArgs _otr_event_args = null;
        OTRMessage _dh_commit_message = null;
        OTRSessionObjects _otr_session_object = null;
        OTRFragmentObject _otr_fragment_object = null;

        

        OTR_AUTH_STATE _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
        OTR_MESSAGE_STATE _message_state = OTR_MESSAGE_STATE.MSG_STATE_PLAINTEXT;
        OTR.Interface.OTR_SMP_EVENT _smp_event_type_1 = OTR.Interface.OTR_SMP_EVENT.INVALID;
        OTR_SMP_EVENT _smp_event_type_2 = OTR_SMP_EVENT.INVALID;

        
        MessageManager _message_manager = null;
        AKEKeysManager _ake_keys_manager = null;
        DSASigner _dsa_signer = null;
        SignatureManager _signature_manager = null;
        SMPManager _smp_manager = null;
        AKEKeys _ake_keys = null;
        byte[] _aes_key = null;
        byte[] _temp_buffer = null;
        byte[] _temp_buffer_2 = null;
        byte[] _extra_symmetric_key = null;
        byte[] _extra_symmetric_key_temp = null;

        UInt32 _temp_int_32_val = 0;


        string _data_to_send = string.Empty;
        string _smp_message = string.Empty;
        string _user_specified_secret = "Kittens are funny";
        string _my_unique_id = string.Empty;
        string _my_buddy_unique_id = string.Empty;
        string _my_buddy_finger_print = string.Empty;

        Stopwatch _stop_watch = null;


        bool _debug_mode = false;
        bool _re_key_my_dh_keys = false;

        UInt16 _smp_max_fragement_length = 0;


        #endregion

        #region   Constructors


        public OTRSession(string my_unique_id, string my_buddy_unique_id, DSAKeyParams dsa_key_hex_strings)
            : this(my_unique_id, my_buddy_unique_id, dsa_key_hex_strings, false)
        {


        }

        public OTRSession(string my_unique_id, string my_buddy_unique_id, DSAKeyParams dsa_key_hex_strings, bool debug_mode)
        {
            if (dsa_key_hex_strings == null)
                throw new ArgumentException("OTRSession: The DSA key hex string object cannot be null");

            if (string.IsNullOrEmpty(my_unique_id))
                throw new ArgumentException("OTRSession:My uique ID cannot be null/empty");

            if (string.IsNullOrEmpty(my_buddy_unique_id))
                throw new ArgumentException("OTRSession:My buddy's unique ID cannot be null/empty");


            if (my_buddy_unique_id.Equals(my_unique_id))
                throw new ArgumentException("OTRSession:My uique ID and My buddy's unique ID cannot be the same value");


            _my_unique_id = my_unique_id;
            _my_buddy_unique_id = my_buddy_unique_id;



            _ake_keys_manager = new AKEKeysManager();
            _otr_session_object = new OTRSessionObjects();


            _dsa_signer = new DSASigner(dsa_key_hex_strings);
            _signature_manager = new SignatureManager(_dsa_signer);


            _debug_mode = debug_mode;





        }
       

        public OTRSession(string my_unique_id, string my_buddy_unique_id, bool debug_mode) :
            this(my_unique_id, my_buddy_unique_id)
        {

            _debug_mode = debug_mode;

        }

        public OTRSession(string my_unique_id, string my_buddy_unique_id)
        {


            if (string.IsNullOrEmpty(my_unique_id))
                throw new ArgumentException("OTRSession:My uique ID cannot be null/empty");

            if (string.IsNullOrEmpty(my_buddy_unique_id))
                throw new ArgumentException("OTRSession:My buddy's unique ID cannot be null/empty");


            if (my_buddy_unique_id.Equals(my_unique_id))
                throw new ArgumentException("OTRSession:My uique ID and My buddy's unique ID cannot be the same value");


            _my_unique_id = my_unique_id;
            _my_buddy_unique_id = my_buddy_unique_id;




            _ake_keys_manager = new AKEKeysManager();
            _otr_session_object = new OTRSessionObjects();


            _dsa_signer = new DSASigner();
            _signature_manager = new SignatureManager(_dsa_signer);


        }


        #endregion        

        #region   Encrypt and Send message functions

        public void StartOTRSession(string otr_version_string)
        {

            OTR_VERSION _otr_version = Utility.GetOTRVersion(otr_version_string);

            if (_otr_version == OTR_VERSION.INVALID)
            throw new ArgumentException("StartOTRSession:The OTR Version is unsupported or invalid");

            SetOTRVersion(_otr_version);

            _aes_key = Utility.GetRandomByteArray(OTRConstants.AES_KEY_LENGTH_BITS / 8);

           

            byte[] _dh_commit_message = _message_manager.FormatDHCommit(_otr_session_object.GetMyRecentDHKeyPair().GetDHPublicKeyData(_aes_key, _otr_session_object.GetCounter()));

            _authentication_state = OTR_AUTH_STATE.AUTH_STATE_AWAITING_DH_KEY;

            DebugPrint("Sending DH Commit Message");

            SendOTRMessage(_dh_commit_message);



        }
        public void EndOTRSession()
        {
            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EndOTRSession:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("EndOTRSession:The OTR session object cannot be null");



            byte[] _encoded_tlv_end_bytes = null;

            Utility.EncodeTLVDisconnected(ref _encoded_tlv_end_bytes);



            if (_encoded_tlv_end_bytes == null || _encoded_tlv_end_bytes.Length < 1)
                throw new ApplicationException("EndOTRSession: The encoded OTR end session array cannot be null/empty");


            byte[] _message_byte_array = FormatMessageWtTLV(null, _encoded_tlv_end_bytes, null);


            if (_message_byte_array == null)
                throw new ApplicationException("EndOTRSession: The message byte array cannot be null/empty");


            EncryptMessage(_message_byte_array,false);

            Thread.Sleep(50);


            CloseOTRSession("OTR Session closed");

        }

        private void EncryptMessage(byte[] message_byte_array, bool is_extra_key_request)
        {

            byte[] _message_data = FormatMessage(message_byte_array,is_extra_key_request);

            DebugPrint("Sending Data Message");

            SendOTRMessage(_message_data);


        }
        public void EncryptMessage(string message_string)
        {
            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("EncryptMessage: The message string cannot be null/empty");


           
            EncryptMessage(UTF8Encoding.UTF8.GetBytes(message_string),false);

        }
        public void EncryptMessage(string message_string, UInt16 padding_length_bytes)
        {

            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("EncryptMessage: The message string cannot be null/empty");

            if (padding_length_bytes < 1)
                throw new ArgumentException("EncryptMessage: The length of the padding cannot be less than 1");


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptMessage:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("EncryptMessage:The OTR session object cannot be null");



            _temp_buffer = Utility.GetRandomByteArray(padding_length_bytes);

            byte[] _encoded_padding_bytes = null;

            Utility.EncodeTLVPadding(_temp_buffer, ref _encoded_padding_bytes);


            byte[] _message_byte_array = FormatMessageWtTLV(message_string, _encoded_padding_bytes, null);

            if (_message_byte_array == null)
                throw new ApplicationException("EncryptMessage: The message byte array cannot be null/empty");

            EncryptMessage(_message_byte_array,false);

        }
        public void EncryptMessage(string message_string, bool start_smp, UInt16 padding_length_bytes)
        {

            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("EncryptMessage: The message string cannot be null/empty");


            if (padding_length_bytes < 1)
                throw new ArgumentException("EncryptMessage: The length of the padding cannot be less than 1");


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptMessage:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("EncryptMessage:The OTR session object cannot be null");

            byte[] _encoded_padding_bytes = null;
            byte[] _encoded_smp_bytes = null;

            _temp_buffer = Utility.GetRandomByteArray(padding_length_bytes);

            Utility.EncodeTLVPadding(_temp_buffer, ref _encoded_padding_bytes);



            if (start_smp == true)
            {
                StartSMPSession(true);
                _encoded_smp_bytes = _smp_manager.FormatSMPMessage1();
            }


            byte[] _message_byte_array = FormatMessageWtTLV(message_string, _encoded_padding_bytes, _encoded_smp_bytes);

            if (_message_byte_array == null)
                throw new ApplicationException("EncryptMessage: The message byte array cannot be null/empty");

            EncryptMessage(_message_byte_array, false);

        }
        public void EncryptMessage(bool start_smp, UInt16 padding_length_bytes)
        {
            if (padding_length_bytes < 1)
                throw new ArgumentException("EncryptMessage: The length of the padding cannot be less than 1");

            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptMessage:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("EncryptMessage:The OTR session object cannot be null");

            _temp_buffer = Utility.GetRandomByteArray(padding_length_bytes);

            byte[] _encoded_padding_bytes = null;
            byte[] _encoded_smp_bytes = null;

            Utility.EncodeTLVPadding(_temp_buffer, ref _encoded_padding_bytes);


            if (start_smp == true)
            {

                StartSMPSession(true);
                _encoded_smp_bytes = _smp_manager.FormatSMPMessage1();
            }


            byte[] _message_byte_array = FormatMessageWtTLV(null, _encoded_padding_bytes, _encoded_smp_bytes);

            if (_message_byte_array == null)
                throw new ApplicationException("EncryptMessage: The message byte array cannot be null/empty");






            EncryptMessage(_message_byte_array, false);




        }
        public void EncryptMessage(string message_string, bool start_smp)
        {

            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("EncryptMessage: The message string cannot be null/empty");

            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptMessage:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("EncryptMessage:The OTR session object cannot be null");

            byte[] _encoded_smp_bytes = null;


            if (start_smp == true)
            {
                StartSMPSession(true);
                _encoded_smp_bytes = _smp_manager.FormatSMPMessage1();
            }



            byte[] _message_byte_array = FormatMessageWtTLV(message_string, _encoded_smp_bytes, null);


            if (_message_byte_array == null)
                throw new ApplicationException("EncryptMessage: The message byte array cannot be null/empty");



            EncryptMessage(_message_byte_array, false);



        }
        public  void EncryptFragments(string message_string, UInt16 max_fragement_length)
        {

            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("EncryptFragments: The message string cannot be null/empty");


            if (max_fragement_length < 1)
                throw new ArgumentException("EncryptFragments: The maximum length of fragements cannot be less than 1");


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptFragments:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
            throw new ApplicationException("EncryptFragments:The OTR session object cannot be null");

           
            byte[] _message_bytes = null;


            _message_bytes = UTF8Encoding.UTF8.GetBytes(message_string);
            

            EncryptFragments(_message_bytes, max_fragement_length);

        }
        private void EncryptFragments(byte [] message_bytes, UInt16 max_fragement_length)
        {
            if (message_bytes == null || message_bytes.Length < 1)
                throw new ArgumentException("EncryptFragments: The message byte cannot be null/empty");


            if (max_fragement_length < 1)
                throw new ArgumentException("EncryptFragments: The maximum length of fragements cannot be less than 1");


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("EncryptFragments:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
              throw new ApplicationException("EncryptFragments:The OTR session object cannot be null");

            byte[] _formatted_message = FormatMessage(message_bytes, false);

            string _data_string_64 = Convert.ToBase64String(_formatted_message);

            _data_string_64 = SetHeaderFooter(_data_string_64);

           string [] _fragments = FragmentString(_data_string_64, max_fragement_length);


            for (int i = 0; i < _fragments.Length; i++)
            {
                SendOTRFragement(_fragments[i], Convert.ToUInt16(i + 1), Convert.ToUInt16(_fragments.Length));

            }
            

        }
        public void StartSMP()
        {
            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("StartSMP:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("StartSMP:The OTR session object cannot be null");

            StartSMPSession(true);

            byte[] _encoded_smp_bytes = _smp_manager.FormatSMPMessage1();

            if (_encoded_smp_bytes == null || _encoded_smp_bytes.Length < 1)
                throw new ApplicationException("StartSMP: The encoded SMP byte array cannot be null/empty");


            byte[] _message_byte_array = FormatMessageWtTLV(null, _encoded_smp_bytes, null);

            if (_message_byte_array == null)
            throw new ApplicationException("StartSMP: The message byte array cannot be null/empty");

            if (_smp_max_fragement_length > 0)
            EncryptFragments(_message_byte_array, _smp_max_fragement_length);
            else
                EncryptMessage(_message_byte_array, false);

        }            
        public void AbortSMP()
        {
            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("AbortSMP:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("AbortSMP:The OTR session object cannot be null");

            byte[] _encoded_tlv_abort_bytes = null;

            Utility.EncodeTLVSMPAbort(ref _encoded_tlv_abort_bytes);


            byte[] _message_byte_array = FormatMessageWtTLV(null, _encoded_tlv_abort_bytes, null);


            if (_message_byte_array == null)
                throw new ApplicationException("AbortSMP: The message byte array cannot be null/empty");



            EncryptMessage(_message_byte_array, false);


        }
        public void SendHeartBeat()
        {
            _temp_buffer_2 = new byte[1];
            _temp_buffer_2[0] = OTRConstants.MESSAGE_NULL_BYTE;

            EncryptMessage(_temp_buffer_2, false);

        }
              
         
        public void RequestExtraKeyUse()
        {
            if (_current_otr_version == OTR_VERSION.VERSION_2)
                throw new ApplicationException("OTR version 2 does not support the use of the extra symmetric key");

            _temp_buffer = null;
            byte[] _ecoded_extra_sym_key_request = null;
            Utility.EncodeTLVExtraSymKey(_temp_buffer, ref _ecoded_extra_sym_key_request);


            _temp_buffer = null;
            _temp_buffer = new byte[1];
            _temp_buffer[0] = OTRConstants.MESSAGE_NULL_BYTE;


            byte[] _request_byte_array = new byte[_ecoded_extra_sym_key_request.Length + _temp_buffer.Length];


            Buffer.BlockCopy(_temp_buffer, 0, _request_byte_array, 0, _temp_buffer.Length);
            Buffer.BlockCopy(_ecoded_extra_sym_key_request, 0, _request_byte_array, _temp_buffer.Length, _ecoded_extra_sym_key_request.Length);
            

            EncryptMessage(_request_byte_array,true);


        }

        private byte[] FormatMessage(byte[] message_byte_array, bool is_extra_key_request)
        {

            if (message_byte_array == null || message_byte_array.Length < 1)
                throw new ArgumentException("FormatMessage: The message byte array cannot be null/empty");



            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                throw new ApplicationException("FormatMessage:OTR engine not in the MSG_STATE_ENCRYPTED state");


            if (_otr_session_object == null)
                throw new ApplicationException("FormatMessage:The OTR session object cannot be null");

            DataExchangeKeys _data_exchange_keys = _otr_session_object.GetDataExchangeKeys();


           
           
            byte[] _encoded_my_recent_public_key_id_byte_array = null;
            byte[] _encoded_buddy_recent_public_key_id_byte_array = null;
            byte[] _encoded_my_next_public_key_byte_array = null;
            byte[] _encoded_encrypted_message_byte_array = null;
            byte[] _encoded_counter_top_half_byte_array = null;
            byte[] _message_data = null;
            int _next_index = 0;
            int _temp_buffer_length = 0;

                     
          
            Utility.EncodeOTRInt(_otr_session_object.GetMyRecentDHKeyPair().GetKeyIDBytes(), ref _encoded_my_recent_public_key_id_byte_array);
            Utility.EncodeOTRInt(_otr_session_object.GetBuddyRecentKeyID(), ref _encoded_buddy_recent_public_key_id_byte_array);


            _encoded_my_next_public_key_byte_array = _otr_session_object.GetMyNextDHKeyPair().GetPublicKeyMpiBytes();

             Utility.EncodeOTRCtr(_otr_session_object.GetCounter(), ref _encoded_counter_top_half_byte_array);

             if (is_extra_key_request == true)
             SetExtraSymmetricKey(_data_exchange_keys.GetAESKeyExtra());
                        

            
             _temp_buffer_2 = Utility.AESGetEncrypt(_data_exchange_keys.GetAESKeySend(), message_byte_array, _otr_session_object.GetCounter());
            Utility.EncodeOTRDataBE(_temp_buffer_2, ref _encoded_encrypted_message_byte_array);


            _temp_buffer_length = _encoded_my_recent_public_key_id_byte_array.Length;
            _temp_buffer_length += _encoded_buddy_recent_public_key_id_byte_array.Length;
            _temp_buffer_length += _encoded_my_next_public_key_byte_array.Length;
            _temp_buffer_length += _encoded_counter_top_half_byte_array.Length;
            _temp_buffer_length += _encoded_encrypted_message_byte_array.Length;


            _temp_buffer = new byte[_temp_buffer_length];

            Buffer.BlockCopy(_encoded_my_recent_public_key_id_byte_array, 0, _temp_buffer, _next_index, _encoded_my_recent_public_key_id_byte_array.Length);
            _next_index += _encoded_my_recent_public_key_id_byte_array.Length;

            Buffer.BlockCopy(_encoded_buddy_recent_public_key_id_byte_array, 0, _temp_buffer, _next_index, _encoded_buddy_recent_public_key_id_byte_array.Length);
            _next_index += _encoded_buddy_recent_public_key_id_byte_array.Length;

            Buffer.BlockCopy(_encoded_my_next_public_key_byte_array, 0, _temp_buffer, _next_index, _encoded_my_next_public_key_byte_array.Length);
            _next_index += _encoded_my_next_public_key_byte_array.Length;

            Buffer.BlockCopy(_encoded_counter_top_half_byte_array, 0, _temp_buffer, _next_index, _encoded_counter_top_half_byte_array.Length);
            _next_index += _encoded_counter_top_half_byte_array.Length;

            Buffer.BlockCopy(_encoded_encrypted_message_byte_array, 0, _temp_buffer, _next_index, _encoded_encrypted_message_byte_array.Length);


          
            _temp_buffer_2 = null;
            /* MAC key computed for the last received message */
            if (_otr_session_object.GetOldMacKeys() != null  && _otr_session_object.GetOldMacKeys().Count > 1)
            {
                int _next_i = 0;
                _temp_buffer_2 = new byte[_otr_session_object.GetOldMacKeys().Count * OTRConstants.TYPE_LEN_MAC];

                for (int i = 0; i < _otr_session_object.GetOldMacKeys().Count; i++ )
                {
                    Buffer.BlockCopy(_otr_session_object.GetOldMacKeys()[i], 0, _temp_buffer_2, _next_i, 
                      OTRConstants.TYPE_LEN_MAC);
                    _next_i += OTRConstants.TYPE_LEN_MAC;
            

                }

                _otr_session_object.ClearOldMacList();
               
          }

            

            _message_data = _message_manager.FormatData(_temp_buffer, _temp_buffer_2, _data_exchange_keys.GetMACKeySend());

            _re_key_my_dh_keys = true;
          
            return _message_data;

        }
        private byte[] FormatMessageWtTLV(string message_string, byte[] encoded_tlv_1, byte[] encoded_tlv_2)
        {
            _temp_buffer = null;
            _temp_buffer_2 = new byte[1];
            _temp_buffer_2[0] = OTRConstants.MESSAGE_NULL_BYTE;
            int _message_buffer_length = _temp_buffer_2.Length;
            int _next_index = 0;

            if (encoded_tlv_1 != null && encoded_tlv_1.Length > 0)
                _message_buffer_length += encoded_tlv_1.Length;


            if (encoded_tlv_2 != null && encoded_tlv_2.Length > 0)
                _message_buffer_length += encoded_tlv_2.Length;


            if (string.IsNullOrEmpty(message_string) == false)
            {
                _temp_buffer = UTF8Encoding.UTF8.GetBytes(message_string);
                _message_buffer_length += _temp_buffer.Length;
            }


            if (_message_buffer_length < 1)
                return null;


            byte[] _message_byte_array = new byte[_message_buffer_length];


            if (_temp_buffer != null && _temp_buffer.Length > 0)
            {
                Buffer.BlockCopy(_temp_buffer, 0, _message_byte_array, _next_index, _temp_buffer.Length);
                _next_index += _temp_buffer.Length;
            }

            /* Null byte */
            Buffer.BlockCopy(_temp_buffer_2, 0, _message_byte_array, _next_index, _temp_buffer_2.Length);
            _next_index += _temp_buffer_2.Length;


            if (encoded_tlv_1 != null && encoded_tlv_1.Length > 0)
            {
                Buffer.BlockCopy(encoded_tlv_1, 0, _message_byte_array, _next_index, encoded_tlv_1.Length);
                _next_index += encoded_tlv_1.Length;

            }

            if (encoded_tlv_2 != null && encoded_tlv_2.Length > 0)
            {
                Buffer.BlockCopy(encoded_tlv_2, 0, _message_byte_array, _next_index, encoded_tlv_2.Length);
                _next_index += encoded_tlv_2.Length;

            }


            return _message_byte_array;
        }

        private void SendOTRMessage(byte[] message_data)
        {

            if (message_data == null || message_data.Length < 1)
                throw new ArgumentException("SendOTRMessage: The message byte array to be sent cannot be null/empty");

            try
            {
                _data_to_send = SetHeaderFooter(message_data);

                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage(_data_to_send);
                _otr_event_args.SetOTREvent(OTR_EVENT.SEND);
            }
            catch (Exception ex)
            {

                _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);
                _otr_event_args.SetErrorVerbose("SendOTRMessage:" + ex.ToString());
                _otr_event_args.SetErrorMessage("SendOTRMessage:Internal OTR error");


            }


            DoOTREvent(_otr_event_args);




        }

        private void SendOTRFragement(string fragment_string, UInt16 fragment_number, UInt16 total_number_of_fragments)
        {

            if (string.IsNullOrEmpty(fragment_string) == true)
                throw new ArgumentException("SendOTRFragement: The fragment string to be sent cannot be null/empty");


            if (fragment_number > total_number_of_fragments)
                throw new ArgumentException("SendOTRFragement: The fragment number cannot exceed the the total number of fragments");



            try
            {

                _data_to_send = SetFragmentHeaderFooter(fragment_string, fragment_number, total_number_of_fragments);                
                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage(_data_to_send);
                _otr_event_args.SetOTREvent(OTR_EVENT.SEND);

              
            }
            catch (Exception ex)
            {

                _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);
                _otr_event_args.SetErrorVerbose("SendOTRFragement:" + ex.ToString());
                _otr_event_args.SetErrorMessage("SendOTRFragement:Internal OTR error");


            }

            DoOTREvent(_otr_event_args);


        }

        #endregion

        #region  Process OTR  message functions


        public  void ProcessMessage(string otr_message_string)
        {
            if (Utility.IsStringExist(otr_message_string, OTRConstants.OTR_ERROR) == true)
            {
                ProcessOTRError(otr_message_string);
                return;

            }
            if ((otr_message_string.Substring(0, 5).Equals(OTRConstants.OTR_FRAGMENT_HEADER + "|") == true ||
            otr_message_string.Substring(0, 5).Equals(OTRConstants.OTR_FRAGMENT_HEADER + ",") == true) &&
            otr_message_string.Substring(otr_message_string.Length - 1, 1).Equals(OTRConstants.OTR_FRAGMENT_FOOTER))
            {

                ProcessOTRFragment(otr_message_string);
                return;

            }
            else if (otr_message_string.Substring(0, 5).Equals(OTRConstants.OTR_MESSAGE_HEADER) == true &&
                otr_message_string.Substring(otr_message_string.Length - 1, 1).Equals(OTRConstants.OTR_MESSAGE_FOOTER))
            {
                
                ProcessOTRMessage(otr_message_string);
                return;

            }




        }
        private void ProcessOTRError(string otr_message_string)
        {
            string _temp_string = otr_message_string.Substring(0, 11);
            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);

            if (_temp_string.Equals(OTRConstants.OTR_ERROR) == false)
            {
                OTRError("ProcessOTRError: Received OTR message not properly formatted",
               "ProcessOTRError: Received OTR message not properly formatted", null);

            }
            else
            {

                _temp_string = otr_message_string.Substring(11, otr_message_string.Length - 11);


                if (!string.IsNullOrEmpty(_temp_string))
                    OTRError("ProcessOTRError: (Error Message from " + _my_buddy_unique_id + ") " + _temp_string,
                      "ProcessOTRError: (Error Message from " + _my_buddy_unique_id + ") " + _temp_string, null);


            }

        }
        private void ProcessOTRFragment(string otr_fragment_string)
        {



            if (_otr_fragment_object == null)
                _otr_fragment_object = new OTRFragmentObject();

            string _string_1 = string.Empty;
            string _string_2 = string.Empty;
            string[] _parts = null;

            _string_1 = otr_fragment_string.Substring(4, otr_fragment_string.Length - 5);


            if (_current_otr_version != OTR_VERSION.VERSION_2)
            {

                if (_string_1.Substring(0, 1).Equals("|") == false)
                {
                    OTRError("ProcessOTRFragment:Fragment not properly formatted", null, null);
                    return;
                }

                _string_1 = _string_1.Substring(1, _string_1.Length - 1);

                _parts = _string_1.Split(new char[] { '|' }, 2);

                UInt32 _sender_instance_tag = Convert.ToUInt32(_parts[0].Trim());

                if (_sender_instance_tag != _message_manager.GetBuddyIntanceTag())
                {
                    OTRError("ProcessOTRFragment:Invalid sender instance tag", null, null);
                    return;
                }
                  

                _parts = _parts[1].Split(new char[] { ',' }, 2);




                UInt32 _receiver_instance_tag = Convert.ToUInt32(_parts[0].Trim());

                if (_receiver_instance_tag != _message_manager.GetMyIntanceTag())
                {
                    OTRError("ProcessOTRFragment:Invalid receiver instance tag", null, null);
                    return;
                }
                  
                   




            }
            else
                _parts = _string_1.Split(new char[] { ',' }, 2);


            _parts = _parts[1].Split(new char[] { ',' }, 2);

            UInt16 _fragment_number = Convert.ToUInt16(_parts[0].Trim());


            _parts = _parts[1].Split(new char[] { ',' }, 2);


            UInt16 _total_number_fragments = Convert.ToUInt16(_parts[0].Trim());


            DebugPrint("Received fragment " + _fragment_number.ToString() + " of " + _total_number_fragments.ToString());



            if (_otr_fragment_object.IsSetFragment(_parts[1], _fragment_number, _total_number_fragments) == false)
            {
                OTRError("ProcessOTRFragment:Fragment number " + _fragment_number.ToString() + " of " + _total_number_fragments.ToString() + " was discarded", null, null);
                return;
            }
               

            if (_fragment_number == _total_number_fragments)
            ProcessOTRMessage(_otr_fragment_object.GetCombinedString());





        }

        private void ProcessOTRMessage(string otr_message_string)
        {
            byte[] _message_byte_array = null;


            try
            {


                RemoveHeaderFooter(otr_message_string, ref _message_byte_array);

                if (_message_byte_array == null || _message_byte_array.Length < 1)
                {
                    OTRError("The OTR data byte array cannot be null/empty", null, null);
                    return;
                }
                  

                OTR_VERSION _otr_version = MessageManager.GetMessageOTRVersion(_message_byte_array);

                if (_current_otr_version == OTR_VERSION.INVALID)
                {

                    if (_otr_version == OTR_VERSION.INVALID)
                    {
                        OTRError("ProcessMessage: Received OTR version not supported.",
                           "ProcessMessage: Received OTR version not supported.",
                           null);

                        return;
                    }

                    else
                        SetOTRVersion(_otr_version);
                }
                else if (_current_otr_version != _otr_version)
                {

                    OTRError("ProcessMessage: Received OTR version is invalid.",
                          "ProcessMessage: Received OTR version is invalid.",
                          null);

                    return;

                }



                if (_message_byte_array == null || _message_byte_array.Length < 1)
                    return;


                _otr_message = _message_manager.ExtractMessage(_message_byte_array);




                if (_otr_message == null)
                {
                    OTRError("Received OTR message not properly formatted", null, "Message not properly formatted.");
                    return;
                }
                



                switch (_otr_message.GetMessageType())
                {

                    case OTR_MESSAGE_TYPE.DH_COMMIT:



                        ProcessDHCommitMessage(_otr_message);


                        break;
                    case OTR_MESSAGE_TYPE.DH_KEY:

                        ProcessDHKeyMessage(_otr_message);


                        break;
                    case OTR_MESSAGE_TYPE.REVEAL_SIGNATURE:

                        ProcessRevealSigMessage(_otr_message);


                        break;
                    case OTR_MESSAGE_TYPE.SIGNATURE:

                        ProcessSignatureMessage(_otr_message);


                        break;
                    case OTR_MESSAGE_TYPE.DATA:

                        ProcessDataMessage(_otr_message);


                        break;
                    default:

                        OTRError("ProcessMessage: Invalid Message type.",
                          "ProcessMessage: Invalid Message type.",
                          "Message not properly formatted.");
                      
                    break;

                }






            }
            catch (Exception ex)
            {

                OTRError("ProcessOTRMesaage: Received OTR message not properly formatted",
                "ProcessOTRMesaage:" + ex.ToString(),
                "Message not properly formatted.");

                return;


            }






        }
        private void ProcessDHCommitMessage(OTRMessage otr_message)
        {
            DebugPrint("Received DH Commit Message");


            if (_authentication_state != OTR_AUTH_STATE.AUTH_STATE_NONE)
            {

                OTRError("ProcessDHCommitMessage: OTR Engine is not in the AUTH_STATE_NONE state", "ProcessDHCommitMessage: OTR Engine is not in the AUTH_STATE_NONE state",
                null);

                return;

            }





            _dh_commit_message = otr_message;


                       
            byte[] _dh_key_message = _message_manager.FormatDHKey(_otr_session_object.GetMyRecentDHKeyPair().GetPublicKeyMpiBytes());


            _authentication_state = OTR_AUTH_STATE.AUTH_STATE_AWAITING_REVEAL_SIG;


            DebugPrint("Sending DH Key Message");
            SendOTRMessage(_dh_key_message);





        }
        private void ProcessDHKeyMessage(OTRMessage otr_message)
        {
            DebugPrint("Received DH Key Message");

            _otr_event_args = new OTREventArgs();



            if (_authentication_state != OTR_AUTH_STATE.AUTH_STATE_AWAITING_DH_KEY)
            {

                OTRError("ProcessDHKeyMessage: OTR Engine is not in the AUTH_STATE_AWAITING_DH_KEY state", "ProcessDHKeyMessage: OTR Engine is not in the AUTH_STATE_AWAITING_DH_KEY state",
                null);


                return;

            }

            if (otr_message.GetGxMpi() == null || otr_message.GetGxMpi().Length < 1)
            {
                OTRError("ProcessDHKeyMessage: The received MPI encoded public key byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                return;
            }
               


            if (_otr_session_object.IsSetBuddyFirstPublicKey(otr_message.GetGxMpi()) == false)
            {


                OTRError("ProcessDHKeyMessage:" + _my_buddy_unique_id + "'s DH public key is invalid",
                    "ProcessDHKeyMessage:" + _my_buddy_unique_id + "'s DH public key is invalid",
               "OTR Failed. Unexpected error");

                return;
            }




       _ake_keys = _ake_keys_manager.ComputeKeys(_otr_session_object.GetMyRecentDHKeyPair(), _otr_session_object.GetBuddyRecentPublicKey());



            _signature_manager.ComputeSignature(_ake_keys, _otr_session_object.GetMyRecentDHKeyPair().GetPublicKeyMpiBytes(), _otr_session_object.GetMyRecentDHKeyPair().GetKeyIDBytes(),
                 otr_message.GetGxMpi(), _otr_session_object.GetCounter(), true);



            if (_aes_key == null || _aes_key.Length < 1)
            {
                OTRError("ProcessDHKeyMessage: The AES key byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                return;
            }
               

            Utility.EncodeOTRDataBE(_aes_key, ref _temp_buffer);

            _temp_buffer_2 = new byte[_temp_buffer.Length + _signature_manager.GetSignatureDataLength()];

            Buffer.BlockCopy(_temp_buffer, 0, _temp_buffer_2, 0, _temp_buffer.Length);
            Buffer.BlockCopy(_signature_manager.GetSignatureDataBytes(), 0, _temp_buffer_2, _temp_buffer.Length, _signature_manager.GetSignatureDataLength());


            byte[] _dh_reveal_byte_array = _message_manager.FormatRevealSig(_temp_buffer_2);


            _authentication_state = OTR_AUTH_STATE.AUTH_STATE_AWAITING_SIG;



            DebugPrint("Sending Reveal Signature Message");
            SendOTRMessage(_dh_reveal_byte_array);


        }
        private void ProcessRevealSigMessage(OTRMessage otr_message)
        {
            DebugPrint("Received Reveal Signature Message");

            _otr_event_args = new OTREventArgs();



            if (_authentication_state != OTR_AUTH_STATE.AUTH_STATE_AWAITING_REVEAL_SIG)
            {
                OTRError("ProcessRevealSigMessage: OTR Engine is not in the AUTH_STATE_AWAITING_REVEAL_SIG state",
                  "ProcessRevealSigMessage: OTR Engine is not in the AUTH_STATE_AWAITING_REVEAL_SIG state",
             null);


                return;

            }


            if (otr_message.GetRevealedKey() == null || otr_message.GetRevealedKey().Length < 1)
            {
                OTRError("ProcessRevealSigMessage: The AES revealed key byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                 return;
            }
               

            if (otr_message.GetEncodedEncryptedSignature() == null || otr_message.GetEncodedEncryptedSignature().Length < 1)
            {
                OTRError("ProcessRevealSigMessage: The encoded encrypted signature byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                return;
            }
                


            if (otr_message.GetMacDSignature() == null || otr_message.GetMacDSignature().Length < 1)
            {
                OTRError("ProcessRevealSigMessage: The MAC'd signature byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                return;
            }
               



            _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);





            if (_dh_commit_message == null || _dh_commit_message.GetEncryptedGxMpi() == null || _dh_commit_message.GetEncryptedGxMpi().Length < 1)
            {
                OTRError("ProcessRevealSigMessage: The MPI encoded encrypted public key (g^x mpi) should not be null/empty",
                  "ProcessRevealSigMessage: The MPI encoded encrypted public key (g^x mpi) should not be null/empty",
             "OTR Failed. Unexpected error");

                return;

            }



            if (_otr_session_object.IsSetMyBuddyFirstPublicKey(otr_message.GetRevealedKey(), _dh_commit_message.GetEncryptedGxMpi(),
                _dh_commit_message.GetHashedGxMpi()) == false)
            {

                OTRError("ProcessRevealSigMessage: The MPI encoded decrypted public key (g^x mpi) should not be null/empty",
                "ProcessRevealSigMessage: The MPI encoded decrypted public key (g^x mpi) should not be null/empty",
                "OTR Failed. Unexpected error");
                return;

            }




            _ake_keys = _ake_keys_manager.ComputeKeys(_otr_session_object.GetMyRecentDHKeyPair(), _otr_session_object.GetBuddyRecentPublicKey());

            byte[] dsa_public_key_byte_array_encoded = null;

            bool _is_sig_verified = SignatureManager.IsSignatureVerified(_ake_keys, _otr_session_object.GetMyRecentDHKeyPair(), _otr_session_object.GetBuddyRecentPublicKeyMpi(),
                otr_message.GetEncodedEncryptedSignature(), otr_message.GetMacDSignature(), true, ref _temp_int_32_val, ref dsa_public_key_byte_array_encoded);

            if (_otr_session_object.IsComputeBuddyFingerPrint(dsa_public_key_byte_array_encoded) == false)
            {

                OTRError("ProcessRevealSigMessage:" + _my_buddy_unique_id + "'s DSA public key fingerprint computation failed",
                 "ProcessRevealSigMessage:" + _my_buddy_unique_id + "'s DSA public key fingerprint computation failed",
                 null);
                _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
                return;
            }


            if (_is_sig_verified != true)
            {

                OTRError("ProcessRevealSigMessage:" + _my_buddy_unique_id + "'s signature verification failed",
                   "ProcessRevealSigMessage:" + _my_buddy_unique_id + "'s signature verification failed",
                  "OTR Failed. Unexpected error");

                _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;

                return;
            }







            _signature_manager.ComputeSignature(_ake_keys, _otr_session_object.GetMyRecentDHKeyPair().GetPublicKeyMpiBytes(), _otr_session_object.GetMyRecentDHKeyPair().GetKeyIDBytes(),
           _otr_session_object.GetBuddyRecentPublicKeyMpi(), _otr_session_object.GetCounter(), false);

            //Send signature message
            byte[] _dh_signature_byte_array = _message_manager.FormatSignature(_signature_manager.GetSignatureDataBytes());

            DebugPrint("Sending Signature Message");
            SendOTRMessage(_dh_signature_byte_array);


            

            /* Inform client of OTR readiness  */
            _otr_session_object.SetFirstBuddyPublicKeyID(_temp_int_32_val);
            _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
            _message_state = OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED;
            _otr_event_args.SetOTREvent(OTR_EVENT.READY);
            _otr_event_args.SetMessage(_my_buddy_unique_id + "'s signature verification successful");


           

            DoOTREvent(_otr_event_args);



        }
        private void ProcessSignatureMessage(OTRMessage otr_message)
        {
            DebugPrint("Received Signature Message");

            _otr_event_args = new OTREventArgs();



            if (_authentication_state != OTR_AUTH_STATE.AUTH_STATE_AWAITING_SIG)
            {


                OTRError("ProcessSignatureMessage: OTR Engine is not in the AUTH_STATE_AWAITING_SIG state",
                  "ProcessSignatureMessage: OTR Engine is not in the AUTH_STATE_AWAITING_SIG state",
                 null);


                return;

            }

            if (otr_message.GetEncodedEncryptedSignature() == null || otr_message.GetEncodedEncryptedSignature().Length < 1)
            {
                OTRError("ProcessSignatureMessage: The encoded encrypted signature byte array cannot be null/empty", null,
                    "OTR Failed. Unexpected error");
                return;
            }
                

            if (otr_message.GetMacDSignature() == null || otr_message.GetMacDSignature().Length < 1)
              {
                    OTRError("ProcessSignatureMessage: The MAC'd signature byte array cannot be null/empty", null,
                        "OTR Failed. Unexpected error");
                    return;
                }
               

            _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);

            byte[] dsa_public_key_byte_array_encoded = null;

            bool _is_sig_verified = SignatureManager.IsSignatureVerified(_ake_keys, _otr_session_object.GetMyRecentDHKeyPair(), _otr_session_object.GetBuddyRecentPublicKeyMpi(),
                otr_message.GetEncodedEncryptedSignature(), otr_message.GetMacDSignature(), false, ref _temp_int_32_val, ref dsa_public_key_byte_array_encoded);


            if (_otr_session_object.IsComputeBuddyFingerPrint(dsa_public_key_byte_array_encoded) == false)
            {

                OTRError("ProcessSignatureMessage:" + _my_buddy_unique_id + "'s DSA public key fingerprint computation failed",
                 "ProcessSignatureMessage:" + _my_buddy_unique_id + "'s DSA public key fingerprint computation failed",
                 null);
                _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
                return;
            }


            if (_is_sig_verified != true)
            {

                OTRError("ProcessSignatureMessage:" + _my_buddy_unique_id + "'s signature verification failed",
                    "ProcessSignatureMessage:" + _my_buddy_unique_id + "'s signature verification failed",
                    null);
                _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
                return;
            }



            /* Inform client of OTR readiness  */
            _otr_session_object.SetFirstBuddyPublicKeyID(_temp_int_32_val);
            _authentication_state = OTR_AUTH_STATE.AUTH_STATE_NONE;
            _message_state = OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED;
            _otr_event_args.SetOTREvent(OTR_EVENT.READY);
            _otr_event_args.SetMessage(_my_buddy_unique_id + "'s signature verification successful");

           
            DoOTREvent(_otr_event_args);







        }
        private void ProcessDataMessage(OTRMessage otr_message)
        {
            DebugPrint("Received Data Message");


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
            {


                OTRError("ProcessDataMessage: OTR Engine is not in the MSG_STATE_ENCRYPTED state",
                  "ProcessDataMessage: OTR Engine is not in the MSG_STATE_ENCRYPTED state",
                 null);


                return;

            }


            



            /*Compute new keys */

            DataExchangeKeys _data_exchange_keys = _otr_session_object.GetDataExchangeKeys(otr_message.GetRecipientKeyId(),
                _otr_message.GetSenderKeyId(), _otr_message.GetNextDHPublicKeyMpi(), _re_key_my_dh_keys);

            string _error_string = null;
           

            if (_data_exchange_keys == null)
            {
                if (otr_message.GetFlags() != OTRConstants.IGNORE_UNREADABLE)
                 _error_string = "You transmitted an unreadable encrypted message";
                
                OTRError("ProcessDataMessage: Data exchange keys are null",
                 "ProcessDataMessage: Data exchange keys are null",
                _error_string);
               
                return;
            }


            /* Compute hash with MAC receiving key */

            _temp_buffer = Utility.SHA1GetKeyedHash(_data_exchange_keys.GetMACKeyRecv(), otr_message.GetBytesToAuthenticate());

            /* Compare hashed MAC */

            if (Utility.IsArrayEqual(_temp_buffer, otr_message.GetAuthenticationMAC()) == false)
            {
                
               
                if (otr_message.GetFlags() != OTRConstants.IGNORE_UNREADABLE)
                 _error_string = "You transmitted an unreadable encrypted message";


                OTRError("Message MAC authentication failed", "Message MAC authentication failed", _error_string);


                
                return;

            }


            /* Decrypt message data */


            try
            {

                _temp_buffer = Utility.AESGetDecrypt(_data_exchange_keys.GetAESKeyRecv(),
                 otr_message.GetEncryptedData(), otr_message.GetCounterTopHalf());
                
                _extra_symmetric_key_temp = _data_exchange_keys.GetAESKeyExtra();


               
              
            }
            catch (Exception ex)
            {


                if (otr_message.GetFlags() != OTRConstants.IGNORE_UNREADABLE)
                    _error_string = "You transmitted an unreadable encrypted message";
                else
                    _error_string = string.Empty;

                OTRError("ProcessDataMessage:Unable to decrypte message",
                 "ProcessDataMessage:" + ex.ToString(),
                _error_string);
                _otr_fragment_object = null;

                return;


            }

            /* Process plain text */

            if (_otr_fragment_object != null)
            {
                _otr_fragment_object.ClearCombinedString();
                _otr_fragment_object = null;
            }

          

            ProcessPlaintext(_temp_buffer,_otr_message.GetOldMacKeys());

        }
        private void ProcessPlaintext(byte[] message_bytes, byte [] old_mac_keys)
        {
                       
            if (message_bytes == null || message_bytes.Length < 1 || (message_bytes.Length == 1 && message_bytes[0] == OTRConstants.MESSAGE_NULL_BYTE))
            {
                DebugPrint("Received heartbeat message from " + _my_buddy_unique_id);
                _otr_event_args.SetOTREvent(OTR_EVENT.HEART_BEAT);
                _otr_event_args.SetOldMacKeys(old_mac_keys);
                DoOTREvent(_otr_event_args);
                return;

            }



            byte[] _message_data = null;
            byte[] _tlv_data = null;
            int _tlv_count = -1;

            _tlv_count = SplitDataMessageBytes(message_bytes, ref _message_data, ref _tlv_data);

            ProcessTLVData(_tlv_data, _tlv_count);

            if (_message_data == null || _message_data.Length < 1)
                return;


            string _plain_text = UTF8Encoding.UTF8.GetString(_message_data);

            _otr_event_args.SetOTREvent(OTR_EVENT.MESSAGE);
            _otr_event_args.SetOldMacKeys(old_mac_keys);
            _otr_event_args.SetMessage(_plain_text);

            DoOTREvent(_otr_event_args);





        }

        #endregion

        #region  TLV Processing functions


        private void ProcessTLVData(byte[] tlv_byte_arrays, int tlv_count)
        {


            if (_message_state != OTR_MESSAGE_STATE.MSG_STATE_ENCRYPTED)
                return;

            if (tlv_count < 1 || tlv_byte_arrays == null || tlv_byte_arrays.Length < 1)
                return;


            int _next_index = 0;
            OTR_TLV_TYPE _tlv_type = OTR_TLV_TYPE.INVALID;
            

            for (int i = 0; i < tlv_count; i++)
            {



                /*Get TLV type */
                Utility.DecodeShortFromBytes(tlv_byte_arrays, _next_index, ref _temp_buffer);
                _tlv_type = Utility.GetTLVType(BitConverter.ToUInt16(_temp_buffer, 0));

                if (_tlv_type != OTR_TLV_TYPE.INVALID)
                {



                    /*Decouple TLV data */

                    _temp_buffer = null;
                    _next_index = Utility.DecoupleTLV(tlv_byte_arrays, _next_index, ref _temp_buffer);


                    if (_tlv_type == OTR_TLV_TYPE.PADDING)
                        ProcessTLVPadding(_temp_buffer);
                    else if (_tlv_type == OTR_TLV_TYPE.DISCONNECTED)
                        ProcessTLVDisconnected(_temp_buffer);
                    else if (_tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_1 ||
                        _tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_2 ||
                        _tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_3 ||
                        _tlv_type == OTR_TLV_TYPE.SMP_MESSAGE_4)
                        ProcessTLVSMPMessage(_temp_buffer, _tlv_type);
                    else if (_tlv_type == OTR_TLV_TYPE.SMP_ABORT)
                        ProcessTLVSMPAbort(_temp_buffer);
                    else if (_tlv_type == OTR_TLV_TYPE.EXTRA_SYM_KEY)
                        ProcessTLVExtraSymKey(_temp_buffer);



                    if (_next_index < 1)
                        break;


                }


            }



        }
        private void ProcessTLVPadding(byte[] encoded_padding_bytes)
        {

            byte[] _decoded_padding_bytes = null;

            Utility.DecodeTLV(encoded_padding_bytes, 0, ref _decoded_padding_bytes);

            DebugPrint("Message data from " + _my_buddy_unique_id + " was padded");

            

        }
        private void ProcessTLVDisconnected(byte[] disconnected_bytes)
        {
            DebugPrint("OTR session disconnect message was received from " + _my_buddy_unique_id);


            CloseOTRSession("OTR encrypted session is closed based on request from " + _my_buddy_unique_id);


        }
        private void ProcessTLVSMPAbort(byte[] smp_abort_bytes)
        {
            DebugPrint("Abort SMP message was received from " + _my_buddy_unique_id);

           
            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetMessage("SMP aborted based on request from " + _my_buddy_unique_id);
            _otr_event_args.SetOTREvent(OTR_EVENT.SMP_MESSAGE);
            _otr_event_args.SetSMPEvent(OTR_SMP_EVENT.ABORT);

            DoOTREvent(_otr_event_args);
            EndSMPSession();



        }
        private void ProcessTLVExtraSymKey(byte[] extra_sym_key_bytes)
        {
            if (_current_otr_version == OTR_VERSION.VERSION_2)
            {
                DebugPrint("Use of extra assymetric key was request from " + _my_buddy_unique_id + " is rejected as this is not supported in OTR version 2");
                return;
            }


            _otr_event_args.SetOTREvent(OTR_EVENT.EXTRA_KEY_REQUEST);
            _otr_event_args.SetMessage("Extra symmetric key use request from " + _my_buddy_unique_id);

            /* set extra symmetric key  */
            SetExtraSymmetricKey(_extra_symmetric_key_temp);
          
                       


            DoOTREvent(_otr_event_args);


        }
        private void ProcessTLVSMPMessage(byte[] smp_byte_data, OTR_TLV_TYPE tlv_type)
        {

            DebugPrint("Received SMP message with TLV of type " + tlv_type.ToString());




            _smp_event_type_1 = OTR_SMP_EVENT.INVALID;
            _smp_event_type_2 = OTR_SMP_EVENT.INVALID;
            _smp_message = string.Empty;




            StartSMPSession(false);

            byte[] _message_byte_array = null;
            byte[] _encoded_smp_bytes = _smp_manager.ProcessSMPMessage(smp_byte_data, tlv_type, ref _smp_event_type_1, ref _smp_event_type_2, ref _smp_message);

            if (_smp_event_type_2 == OTR_SMP_EVENT.SUCCEEDED)
            {
                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage("SMP completed succesfully");
                _otr_event_args.SetOTREvent(OTR_EVENT.SMP_MESSAGE);
                _otr_event_args.SetSMPEvent(OTR_SMP_EVENT.SUCCEEDED);
                

                DoOTREvent(_otr_event_args);

                EndSMPSession();


            }



            if ((_smp_event_type_1 == OTR_SMP_EVENT.SEND) &&
               (_encoded_smp_bytes != null && _encoded_smp_bytes.Length > 0))
            {
                _message_byte_array = FormatMessageWtTLV(null, _encoded_smp_bytes, null);

                if (_smp_max_fragement_length > 0)
                EncryptFragments(_message_byte_array, _smp_max_fragement_length);
                else
                    EncryptMessage(_message_byte_array, false);

            }

            else if (_smp_event_type_1 == OTR_SMP_EVENT.ABORT)
            {

                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage(_smp_message);
                _otr_event_args.SetOTREvent(OTR_EVENT.SMP_MESSAGE);
                _otr_event_args.SetSMPEvent(OTR_SMP_EVENT.ABORT);

                DoOTREvent(_otr_event_args);

                EndSMPSession();

            }

            else if (_smp_event_type_1 == OTR_SMP_EVENT.FAILED)
            {

                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage("Man in the middle attack suspected");
                _otr_event_args.SetOTREvent(OTR_EVENT.SMP_MESSAGE);
                _otr_event_args.SetSMPEvent(OTR_SMP_EVENT.FAILED);

                DoOTREvent(_otr_event_args);

                EndSMPSession();

            }
            else if (_smp_event_type_1 == OTR_SMP_EVENT.SUCCEEDED)
            {

                _otr_event_args = new OTREventArgs();
                _otr_event_args.SetMessage("SMP completed succesfully");
                _otr_event_args.SetOTREvent(OTR_EVENT.SMP_MESSAGE);
                _otr_event_args.SetSMPEvent(OTR_SMP_EVENT.SUCCEEDED);
                DoOTREvent(_otr_event_args);
                EndSMPSession();

            }
            else
            {
                DebugPrint("ProcessTLVSMPMessage:Invalid SMP event");
                EndSMPSession();

            }







        }



        #endregion

        #region  Utility

        public OTR_MESSAGE_STATE GetMessageState()
        {
            return _message_state;
        }
        private void DoOTREvent(OTREventArgs event_args)
        {
            if (event_args == null)
                return;


            try
            {
                               
                event_args.SetSessionID(_my_buddy_unique_id);
                OnOTREvent(this, event_args);
            }
            catch
            {



            }


        }
        public bool IsOTRVersionSupported(string otr_version)
        {
            int _index = OTRConstants.VERSION_LIST().IndexOf(otr_version);

            if (_index > -1)
                return true;

            return false;

        }

        public string GetMyBuddyDSAFingerPrint()
        {

            if (_otr_session_object.GetBuddyDSAFingerPrint() == null || _otr_session_object.GetBuddyDSAFingerPrint().Length < 1)
                return string.Empty;

            return Utility.ByteToHex(_otr_session_object.GetBuddyDSAFingerPrint());
        }
        public string GetMyDSAFingerPrint()
        {
            return _dsa_signer.GetDSAPublicKeyFingerPrintHex();
        }
        public DSAKeyParams GetMyDSAKeyHexParams()
        {
            return _dsa_signer.GetDSAKeyParameters();

        }

        public byte[] GetExtraSymmetricKey()
        {
            if (_current_otr_version == OTR_VERSION.VERSION_2)
                return null;

            return  _extra_symmetric_key;         

        }
        private void SetExtraSymmetricKey(byte[] extra_symmetric_key)
        {

            if (_current_otr_version == OTR_VERSION.VERSION_2)
                return;

            if (extra_symmetric_key == null || extra_symmetric_key.Length < 1)
                return;

            _extra_symmetric_key = new byte[extra_symmetric_key.Length];
            Buffer.BlockCopy(extra_symmetric_key, 0, _extra_symmetric_key, 0, extra_symmetric_key.Length);

            
        }


        public void SetSMPFragLength(UInt16 max_fragement_length)
        {

            if (max_fragement_length < 1)
                _smp_max_fragement_length = 0;
            else
                _smp_max_fragement_length = max_fragement_length;

        }
        public UInt16 GetSMPFragLength()
        {
            return _smp_max_fragement_length;

        }
        public void SetSMPUserSpecSecret(string user_specified_secret)
        {
            if (string.IsNullOrEmpty(user_specified_secret))
                throw new ArgumentException("SetSMPSecret:The user specified SMP secret string cannot be null/empty");

            _user_specified_secret = user_specified_secret;

        }
        public string GetSMPUserSpecSecret()
        {
            return _user_specified_secret;

        }         
        private byte[] GetSMPSecret(bool is_initiator)
        {

            if (string.IsNullOrEmpty(_user_specified_secret))
                throw new ApplicationException("GetSMPSecret:The user specified SMP secret string cannot be null/empty");


            int _smp_secret_byte_length = 0;
            int _next_index = 0;

            byte[] _version = new byte[1];
            _version[0] = OTRConstants.SMP_VERSION;


            byte[] _initiator_finger_print = null;
            byte[] _responder_finger_print = null;
            byte[] _secure_session_id = null;
            byte[] _user_specified_secret_bytes = UTF8Encoding.UTF8.GetBytes(_user_specified_secret);



            if (is_initiator == true)
            {
                _initiator_finger_print = _dsa_signer.GetDSAPublicKeyFingerPrint();
                _responder_finger_print = _otr_session_object.GetBuddyDSAFingerPrint();
            }

            else
            {
                _initiator_finger_print = _otr_session_object.GetBuddyDSAFingerPrint();
                _responder_finger_print = _dsa_signer.GetDSAPublicKeyFingerPrint();

            }


            if (_initiator_finger_print == null || _initiator_finger_print.Length < 1)
                throw new ApplicationException("GetSMPSecret: The SMP Initiator finger print byte array cannot be null/empty");

            if (_responder_finger_print == null || _responder_finger_print.Length < 1)
                throw new ApplicationException("GetSMPSecret: The SMP Responder finger print byte array cannot be null/empty");

            _secure_session_id = _ake_keys.GetSessionID();


            if (_secure_session_id == null || _secure_session_id.Length < 1)
                throw new ApplicationException("GetSMPSecret: The secure session id byte array cannot be null/empty");



            _smp_secret_byte_length += _version.Length;
            _smp_secret_byte_length += _initiator_finger_print.Length;
            _smp_secret_byte_length += _responder_finger_print.Length;
            _smp_secret_byte_length += _secure_session_id.Length;
            _smp_secret_byte_length += _user_specified_secret_bytes.Length;


            byte[] _smp_secret_bytes = new byte[_smp_secret_byte_length];

            Buffer.BlockCopy(_version, 0, _smp_secret_bytes, _next_index, _version.Length);
            _next_index += _version.Length;

            Buffer.BlockCopy(_initiator_finger_print, 0, _smp_secret_bytes, _next_index, _initiator_finger_print.Length);
            _next_index += _initiator_finger_print.Length;

            Buffer.BlockCopy(_responder_finger_print, 0, _smp_secret_bytes, _next_index, _responder_finger_print.Length);
            _next_index += _responder_finger_print.Length;

            Buffer.BlockCopy(_secure_session_id, 0, _smp_secret_bytes, _next_index, _secure_session_id.Length);
            _next_index += _secure_session_id.Length;

            Buffer.BlockCopy(_user_specified_secret_bytes, 0, _smp_secret_bytes, _next_index, _user_specified_secret_bytes.Length);
            _next_index += _user_specified_secret_bytes.Length;


            byte[] _hashed_secret_bytes = Utility.SHA256GetHash(_smp_secret_bytes);


            return _hashed_secret_bytes;

        }
        private void EndSMPSession()
        {
            if (_smp_manager != null)
            {
                _smp_manager.SMPEnd();
                _smp_manager = null;

                DebugPrint("Ending SMP session");

                if (_stop_watch != null)
                {
                    _stop_watch.Stop();
                    string ExecutionTimeTaken = string.Format("{0} Minute(s)  {1} Second(s)   {2} Mili seconds",
                    _stop_watch.Elapsed.Minutes, _stop_watch.Elapsed.Seconds, _stop_watch.Elapsed.TotalMilliseconds);

                    DebugPrint("SMP Execution time: " + ExecutionTimeTaken);

                    _stop_watch = null;


                }


            }

        }       
        private void StartSMPSession(bool is_initiator)
        {
            if (_smp_manager == null)
            {
                _stop_watch = new Stopwatch();
                _stop_watch.Start();

                _smp_manager = new SMPManager();
                _smp_manager.SMPStart(GetSMPSecret(is_initiator));
                DebugPrint("Starting SMP session");
            }

        }
      
         private void SetOTRVersion(OTR_VERSION otr_version)
        {
            _current_otr_version = otr_version;
            _message_manager = new MessageManager(otr_version);

            DebugPrint("Setting OTR Version:" + otr_version);

        }
        private void CloseOTRSession(string session_closed_message)
        {
            DebugPrint("Ending OTR session");

            
            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetMessage(session_closed_message);
            _otr_event_args.SetOTREvent(OTR_EVENT.CLOSED);
            DoOTREvent(_otr_event_args);



            _message_state = OTR_MESSAGE_STATE.MSG_STATE_PLAINTEXT;
            _message_manager = null;
            _ake_keys_manager = null;
            _dsa_signer = null;
            _signature_manager = null;
            _smp_manager = null;
            _ake_keys = null;
            _my_unique_id = string.Empty;
            _my_buddy_unique_id = string.Empty;
            _otr_fragment_object = null;
            EndSMPSession();


        }

        private string SetHeaderFooter(byte[] data_byte_array)
        {
            if (data_byte_array == null || data_byte_array.Length < 1)
                throw new ArgumentException("SetHeaderFooter: The data byte array cannot be null/empty");

            string _data_string_64 = Convert.ToBase64String(data_byte_array);


            return OTRConstants.OTR_MESSAGE_HEADER + _data_string_64 + OTRConstants.OTR_MESSAGE_FOOTER;


        }
        private string SetHeaderFooter(string message_string)
        {
            if (string.IsNullOrEmpty(message_string))
                throw new ArgumentException("SetHeaderFooter: The message string cannot be null/empty");



            return OTRConstants.OTR_MESSAGE_HEADER + message_string + OTRConstants.OTR_MESSAGE_FOOTER;


        }
        private void RemoveHeaderFooter(string otr_message, ref byte[] out_byte_array)
        {
            if (string.IsNullOrEmpty(otr_message))
                throw new ArgumentException("RemoveHeaderFooter: The OTR message string cannot be null/empty");


            if (otr_message.Length < 6)
                throw new ArgumentException("RemoveHeaderFooter: The length of OTR message string should not be less than 6");


            string _temp_string = otr_message.Substring(0, 4);


            if (_temp_string.Equals(OTRConstants.OTR_MESSAGE_HEADER))
                throw new ArgumentException("RemoveHeaderFooter: The OTR message header is invalid");


            _temp_string = otr_message.Substring(otr_message.Length - 1, 1);


            if (!_temp_string.Equals(OTRConstants.OTR_MESSAGE_FOOTER))
                throw new ArgumentException("RemoveHeaderFooter: The OTR message footer is invalid");

            string _data_string_64 = otr_message.Substring(5, otr_message.Length - 6);

            out_byte_array = Convert.FromBase64String(_data_string_64);


        }
        private string SetFragmentHeaderFooter(string fragment_string, UInt16 fragment_number, UInt16 total_number_of_fragments)
        {

            if (string.IsNullOrEmpty(fragment_string))
                throw new ArgumentException("SetFragmentHeaderFooter: The fragment string cannot be null/empty");


            string _string = OTRConstants.OTR_FRAGMENT_HEADER;


            if (_current_otr_version != OTR_VERSION.VERSION_2)
            {
                _string += "|" + _message_manager.GetMyIntanceTag().ToString();
                _string += "|" + _message_manager.GetBuddyIntanceTag().ToString();

            }

            _string += "," + fragment_number.ToString();
            _string += "," + total_number_of_fragments.ToString() + ",";


            _string += fragment_string;


            _string += OTRConstants.OTR_FRAGMENT_FOOTER;


            return _string;

        }


        private void SendError(string error_message)
        {
            error_message = OTRConstants.OTR_ERROR + error_message;

            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetMessage(error_message);
            _otr_event_args.SetOTREvent(OTR_EVENT.SEND);
            DoOTREvent(_otr_event_args);

        }
        private void OTRError(string error_string, string verbose_string, string remote_error_string)
        {


            if (string.IsNullOrEmpty(remote_error_string) == false)
                SendError(remote_error_string);

            if (string.IsNullOrEmpty(verbose_string) == true)
                verbose_string = error_string;

            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetOTREvent(OTR_EVENT.ERROR);
            _otr_event_args.SetErrorVerbose(verbose_string);
            _otr_event_args.SetErrorMessage(error_string);
            DoOTREvent(_otr_event_args);


            // CloseOTRSession("Session closed as a result of OTR error");





        }


        private string[] FragmentString(string string_to_fragment, int max_fragment_length)
        {


            int _max_fragment_length = max_fragment_length;

            int _number_of_fragments = string_to_fragment.Length / _max_fragment_length;

            if (string_to_fragment.Length % _max_fragment_length > 0)
                _number_of_fragments += 1;


            string[] _fragments = new string[_number_of_fragments];

            int _next_index = 0;

            for (int i = 0; i < _fragments.Length; i++)
            {

                if (_next_index + _max_fragment_length > string_to_fragment.Length)
                    _max_fragment_length = string_to_fragment.Length - _next_index;

                _fragments[i] = string_to_fragment.Substring(_next_index, _max_fragment_length);

                _next_index += _max_fragment_length;



            }


            return _fragments;

        }


        private int SplitDataMessageBytes(byte[] data_message_bytes, ref byte[] message_data_array, ref byte[] tlv_data_array)
        {

            if (data_message_bytes == null || data_message_bytes.Length < 1)
             throw new ArgumentException("SplitDataMessageBytes: Data message byte cannot be null/empty");


            int _null_byte_index = -1;
            int _tlv_count = -1;

            for (int i = 0; i < data_message_bytes.Length; i++)
            {
                if (data_message_bytes[i] == OTRConstants.MESSAGE_NULL_BYTE && (data_message_bytes.Length - i) >= 4)
                {
                    _tlv_count = CountTLV(data_message_bytes, i + 1);
                    _null_byte_index = i;
                    break;
                }

            }


            if (_null_byte_index > -1 && _tlv_count > 0)
            {
                message_data_array = new byte[_null_byte_index];
                tlv_data_array = new byte[data_message_bytes.Length - _null_byte_index - 1];
                Buffer.BlockCopy(data_message_bytes, _null_byte_index + 1, tlv_data_array, 0, tlv_data_array.Length);

            }
            else
                message_data_array = new byte[data_message_bytes.Length];


            Buffer.BlockCopy(data_message_bytes, 0, message_data_array, 0, message_data_array.Length);

            return _tlv_count;



        }
        private int CountTLV(byte[] in_byte_array, int start_index)
        {

            int _tlv_count = 0;
            int _next_index = start_index;
            bool _is_valid_tlv = true;



            while (_is_valid_tlv == true && (in_byte_array.Length - _next_index > 3))
            {


                /*check the first two bytes and check the tlv type validity*/
                _is_valid_tlv = IsTLVType(in_byte_array[_next_index], in_byte_array[_next_index + 1]);

                if (_is_valid_tlv == false)
                {
                    _tlv_count = 0;

                    break;
                }


                _tlv_count++;

                /*get the next two bytes to check the length*/
                _next_index += TLVLength(in_byte_array[_next_index + 2], in_byte_array[_next_index + 3]) + (OTRConstants.TYPE_LEN_SHORT * 2);


            }





            return _tlv_count;
        }
        private bool IsTLVType(byte byte_0, byte byte_1)
        {
            //Assumes big endian

            byte[] _tlv_type_array = new byte[2];


            if (BitConverter.IsLittleEndian == true)
            {
                _tlv_type_array[0] = byte_1;
                _tlv_type_array[1] = byte_0;

            }

            else
            {
                _tlv_type_array[0] = byte_0;
                _tlv_type_array[1] = byte_1;
            }



            return Utility.IsTlvType(BitConverter.ToInt16(_tlv_type_array, 0));

        }
        private UInt16 TLVLength(byte byte_2, byte byte_3)
        {
            //Assumes big endian

            byte[] _tlv_type_array = new byte[2];


            if (BitConverter.IsLittleEndian == true)
            {
                _tlv_type_array[0] = byte_3;
                _tlv_type_array[1] = byte_2;

            }

            else
            {
                _tlv_type_array[0] = byte_2;
                _tlv_type_array[1] = byte_3;
            }



            return BitConverter.ToUInt16(_tlv_type_array, 0);

        }

        private void DebugPrint(string debug_text)
        {
            if (_debug_mode == false)
                return;

            _otr_event_args = new OTREventArgs();
            _otr_event_args.SetOTREvent(OTR_EVENT.DEBUG);
            _otr_event_args.SetMessage(debug_text);
            DoOTREvent(_otr_event_args);


        }


        #endregion

        #region Event Function

        public event OTR.Interface.OTREventHandler OnOTREvent;

        #endregion
    }

    class OTRSessionObjects
    {

        DHKeyPair _my_recent_dh_key_pair = null;
        DHKeyPair _my_next_dh_key_pair = null;
        DHKeysManager _dh_key_manager = null;

        BigInteger _my_buddy_recent_dh_public_key = 0;
        BigInteger _my_buddy_old_dh_public_key = 0;
        UInt32 _my_buddy_recent_dh_public_key_id = 0;
        UInt32 _my_buddy_old_dh_public_key_id = 0;




        List<byte[]> _old_rx_mac_keys = null;

        UInt64 _counter = 0;

        byte[] _buddy_dsa_public_key_finger_print = null;
        byte[] _buddy_recent_public_key_mpi = null;


        DataExchangeKeysManager _data_exhange_key_manager = null;
        DataExchangeKeys _recent_data_exchange_keys = null;
        DataExchangeKeys _old_data_exchange_keys = null;
        DataExchangeKeys _data_exchange_keys_holder = null;

        


        public OTRSessionObjects()
        {


           
            _old_rx_mac_keys = new List<byte[]>();
            _dh_key_manager = new DHKeysManager();
            _data_exhange_key_manager = new DataExchangeKeysManager();

            CreateInitialPublicKeys();
        }

       


        private void CreateInitialPublicKeys()
        {
            _my_recent_dh_key_pair = _dh_key_manager.GenerateKeyPair();
            _my_next_dh_key_pair = _dh_key_manager.GenerateKeyPair();

        }

        public DHKeyPair GetMyRecentDHKeyPair()
        {
            return _my_recent_dh_key_pair;
        }
        public DHKeyPair GetMyNextDHKeyPair()
        {
            return _my_next_dh_key_pair;
        }

        public bool IsSetMyBuddyFirstPublicKey(byte[] aes_key, byte[] encrypted_buddy_recent_public_key_mpi_bytes, byte[] hashed_public_key_mpi_bytes)
        {


            if (aes_key == null || aes_key.Length < 1)
                return false;


            if (encrypted_buddy_recent_public_key_mpi_bytes == null || encrypted_buddy_recent_public_key_mpi_bytes.Length < 1)
                return false;


            byte[] _byte_array_holder = Utility.AESGetDecrypt(aes_key, encrypted_buddy_recent_public_key_mpi_bytes, _counter);

            if (_byte_array_holder == null || _byte_array_holder.Length < 1)
                return false;


            if (Utility.IsArrayEqual(Utility.SHA256GetHash(_byte_array_holder), hashed_public_key_mpi_bytes) == false)
                return false;


            BigInteger _key_holder = 0;

            Utility.DecodeMpiFromBytes(_byte_array_holder, 0, ref _key_holder);

            if (Utility.IsValidPublicKey(_key_holder) == false)
                return false;


            _buddy_recent_public_key_mpi = _byte_array_holder;
            _my_buddy_recent_dh_public_key = _key_holder;



            return true;
        }
        public bool IsSetBuddyFirstPublicKey(byte[] buddy_first_public_key_mpi_bytes)
        {
            if (buddy_first_public_key_mpi_bytes == null || buddy_first_public_key_mpi_bytes.Length < 1)
                return false;




            BigInteger _key_holder = 0;


            Utility.DecodeMpiFromBytes(buddy_first_public_key_mpi_bytes, 0, ref _key_holder);

            if (Utility.IsValidPublicKey(_key_holder) == false)
                return false;


            _buddy_recent_public_key_mpi = buddy_first_public_key_mpi_bytes;
            _my_buddy_recent_dh_public_key = _key_holder;

            return true;


        }
        public void SetFirstBuddyPublicKeyID(UInt32 buddy_recent_public_key_id)
        {

            _my_buddy_recent_dh_public_key_id = buddy_recent_public_key_id;


        }
        public BigInteger GetBuddyRecentPublicKey()
        {
            return _my_buddy_recent_dh_public_key;

        }
        public byte[] GetBuddyRecentPublicKeyMpi()
        {

            return _buddy_recent_public_key_mpi;

        }


        public DataExchangeKeys GetDataExchangeKeys(UInt32 my_acked_key_id, UInt32 buddy_key_id, byte[] buddy_key_mpi_bytes, bool re_key_my_dh_keys)
        {

            if (buddy_key_mpi_bytes == null || buddy_key_mpi_bytes.Length < 1)
                return null;


            BigInteger _key_holder = 0;

            Utility.DecodeMpiFromBytes(buddy_key_mpi_bytes, 0, ref _key_holder);

            if (Utility.IsValidPublicKey(_key_holder) == false)
                return null;



            DataExchangeKeys _data_exchange_keys = GetDataExhangeKeys(my_acked_key_id, buddy_key_id);


            ReKeyMyDHKeys(my_acked_key_id, re_key_my_dh_keys);

            ReKeyBuddyKeys(buddy_key_id, _key_holder);


            return _data_exchange_keys;

        }
        public DataExchangeKeys GetDataExchangeKeys()
        {
            _data_exchange_keys_holder = _recent_data_exchange_keys;

            _recent_data_exchange_keys = _data_exhange_key_manager.
            ComputeKeys(_my_recent_dh_key_pair, _my_buddy_recent_dh_public_key);

            _counter++;


            if (_data_exchange_keys_holder != _recent_data_exchange_keys)
            {
                _old_data_exchange_keys = _data_exchange_keys_holder;
                _data_exchange_keys_holder = null;
                AddOldMacKeys(_old_data_exchange_keys);

            }




            return _recent_data_exchange_keys;

        }
        private DataExchangeKeys GetDataExhangeKeys(UInt32 my_key_id, UInt32 buddy_key_id)
        {
            DHKeyPair _my_dh_key_pair_holder = null;
            BigInteger _buddy_public_key_holder = 0;


            if (my_key_id == _my_recent_dh_key_pair.GetKeyID())
                _my_dh_key_pair_holder = _my_recent_dh_key_pair;
            else if (my_key_id == _my_next_dh_key_pair.GetKeyID())
                _my_dh_key_pair_holder = _my_next_dh_key_pair;


            if (buddy_key_id == _my_buddy_recent_dh_public_key_id)
                _buddy_public_key_holder = _my_buddy_recent_dh_public_key;
            else if (buddy_key_id == _my_buddy_old_dh_public_key_id)
                _buddy_public_key_holder = _my_buddy_old_dh_public_key;


                           




            if (_my_dh_key_pair_holder == null || _buddy_public_key_holder == 0)
                return null;

            return _data_exhange_key_manager.ComputeKeys(_my_dh_key_pair_holder, _my_buddy_recent_dh_public_key); ;



        }

        private void ReKeyMyDHKeys(UInt32 acked_key_id, bool re_key_my_key)
        {


            if (re_key_my_key == false)
                return;

            if (acked_key_id != _my_next_dh_key_pair.GetKeyID())
                return;


            _my_recent_dh_key_pair = _my_next_dh_key_pair;
            _my_next_dh_key_pair = _dh_key_manager.GenerateKeyPair();


        }
        private void ReKeyBuddyKeys(UInt32 buddy_key_id, BigInteger buddy_public_key)
        {

            /*is it the same public key we know?   */
            if (buddy_public_key.Equals(_my_buddy_recent_dh_public_key))
                return;


            _my_buddy_old_dh_public_key = _my_buddy_recent_dh_public_key;
            _my_buddy_recent_dh_public_key = buddy_public_key;


            _my_buddy_old_dh_public_key_id = _my_buddy_recent_dh_public_key_id;
            _my_buddy_recent_dh_public_key_id++;





        }

        
        public UInt64 GetCounter()
        {

            return _counter;

        }
        public byte[] GetCounterBytes()
        {

            return BitConverter.GetBytes(GetCounter());

        }
        public byte[] GetBuddyRecentKeyID()
        {
            return BitConverter.GetBytes(_my_buddy_recent_dh_public_key_id);

        }
        public UInt32 GetBuddyRecentKeyIDInt()
        {
            return _my_buddy_recent_dh_public_key_id;

        }

        private void AddOldMacKeys(DataExchangeKeys old_data_exchange_keys)
        {

            if (old_data_exchange_keys == null)
                return;

            _old_rx_mac_keys.Add(old_data_exchange_keys.GetMACKeyRecv());
            _old_rx_mac_keys.Add(old_data_exchange_keys.GetMACKeySend());


        }
        public List<byte[]> GetOldMacKeys()
        {
            return _old_rx_mac_keys;

        }
        public void ClearOldMacList()
        {
            _old_rx_mac_keys.Clear();

        }


        public bool IsComputeBuddyFingerPrint(byte[] buddy_dsa_public_key_encoded)
        {


            if (buddy_dsa_public_key_encoded == null || buddy_dsa_public_key_encoded.Length < 1)
                return false;


            byte[] _temp_buffer = new byte[buddy_dsa_public_key_encoded.Length - 2];

            Buffer.BlockCopy(buddy_dsa_public_key_encoded, 2, _temp_buffer, 0, _temp_buffer.Length);

            _buddy_dsa_public_key_finger_print = Utility.SHA1GetHash(_temp_buffer);



            return true;
        }
        public byte[] GetBuddyDSAFingerPrint()
        {
            return _buddy_dsa_public_key_finger_print;

        }




    }
    
    class OTRFragmentObject
    {
        private string _combined_string = string.Empty;
        private UInt16 _expected_fragment_number = 1;

        public bool IsSetFragment(string fragment_string, UInt16 fragment_number, UInt16 total_number_of_fragments)
        {

            if (string.IsNullOrEmpty(fragment_string))
                return false;

            if (_expected_fragment_number != fragment_number)
                return false;


            if (total_number_of_fragments < fragment_number)
                return false;

            _combined_string += fragment_string;

            _expected_fragment_number++;
            return true;
        }

        public string GetCombinedString()
        {

            return _combined_string;

        }

        public void ClearCombinedString()
        {
            _combined_string = string.Empty;
            _expected_fragment_number = 1;

        }









    }
}

