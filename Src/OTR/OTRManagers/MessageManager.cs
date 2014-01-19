using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;




using OTR.Utilities;
using System.IO;

namespace OTR.Managers
{
    class MessageManager
    {
        
        #region Variables

        byte[] _message_temp_buffer = null;
        byte[] _temp_buffer = null;
        byte[] _temp_buffer_2 = null;
        OTRMessage _otr_message = null;

        private UInt32 _my_instance_tag = 0;
        private UInt32 _buddy_instance_tag = 0;

        byte[] _encoded_my_instance_tag = null;
        byte[] _encoded_receiver_instance_tag = null;


        byte[] _encoded_dh_commit_message_type = null;
        byte[] _encoded_dh_key_message_type = null;
        byte[] _encoded_reveal_message_type = null;
        byte[] _encoded_signature_message_type = null;
        byte[] _encoded_data_message_type = null;

        byte[] _encoded_flag = null;


        int _message_length_1 = 0;
        byte[] _encoded_otr_version_byte_array = null;
        OTR_VERSION _otr_version = OTR_VERSION.INVALID;
        OTR_MESSAGE_TYPE _message_type = OTR_MESSAGE_TYPE.INVALID;

        #endregion


        public MessageManager(OTR_VERSION otr_version)
        {


            if (otr_version == OTR_VERSION.INVALID)
                throw new ArgumentException("MessageManager: The OTR version is invalid");

            _otr_version = otr_version;


            _temp_buffer = null;

            try
            {

                Utility.GetEncodedOtrVersion(otr_version, ref _encoded_otr_version_byte_array);
                _message_length_1 = _encoded_otr_version_byte_array.Length;


                if (_otr_version != OTR_VERSION.VERSION_2)
                {
                    _my_instance_tag = Utility.GetRandomInteger(OTRConstants.MIN_INSTANCE_VALUE);
                    _temp_buffer = BitConverter.GetBytes(_my_instance_tag);

                    Utility.EncodeOTRInt(_temp_buffer, ref _encoded_my_instance_tag);
                    _message_length_1 += _encoded_my_instance_tag.Length * 2;


                }


                _temp_buffer = new byte[1];

                _temp_buffer[0] = OTRConstants.MESSAGE_TYPE_DH_COMMIT;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_dh_commit_message_type);

                _temp_buffer[0] = OTRConstants.MESSAGE_TYPE_DH_KEY;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_dh_key_message_type);

                _temp_buffer[0] = OTRConstants.MESSAGE_TYPE_REVEAL_SIGNATURE;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_reveal_message_type);

                _temp_buffer[0] = OTRConstants.MESSAGE_TYPE_SIGNATURE;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_signature_message_type);

                _temp_buffer[0] = OTRConstants.MESSAGE_TYPE_DATA;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_data_message_type);

                _temp_buffer[0] = 0;
                Utility.EncodeOTRByte(_temp_buffer, ref _encoded_flag);





                _message_length_1 += _encoded_data_message_type.Length;





            }
            catch (Exception ex)
            {
                throw new InvalidDataException("MessageManager:" + ex.ToString());
            }




        }


        #region Format message functions

        public byte[] FormatDHCommit(byte[] message)
        {

            if (message == null || message.Length < 1)
                throw new ArgumentException("FormatDHCommit: The OTR Message byte array cannot be null/empty");




            int _next_index = 0;
            int _message_length_2 = message.Length;
            _message_length_2 += _message_length_1;

            _message_temp_buffer = new byte[_message_length_2];


            Buffer.BlockCopy(_encoded_otr_version_byte_array, 0, _message_temp_buffer, _next_index, _encoded_otr_version_byte_array.Length);
            _next_index += _encoded_otr_version_byte_array.Length;



            Buffer.BlockCopy(_encoded_dh_commit_message_type, 0, _message_temp_buffer, _next_index, _encoded_dh_commit_message_type.Length);
            _next_index += _encoded_dh_commit_message_type.Length;





            if (_otr_version != OTR_VERSION.VERSION_2)
            {
                _temp_buffer = new byte[4];
                _temp_buffer[0] = 0;
                Utility.EncodeOTRInt(_temp_buffer, ref _encoded_receiver_instance_tag);



                Buffer.BlockCopy(_encoded_my_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_my_instance_tag.Length);
                _next_index += _encoded_my_instance_tag.Length;

                Buffer.BlockCopy(_encoded_receiver_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_receiver_instance_tag.Length);
                _next_index += _encoded_receiver_instance_tag.Length;


            }




            Buffer.BlockCopy(message, 0, _message_temp_buffer, _next_index, message.Length);



            return _message_temp_buffer;


        }
        public byte[] FormatDHKey(byte[] message)
        {


            if (message == null || message.Length < 1)
                throw new ArgumentException("FormatDHKey: The OTR Message byte array cannot be null/empty");

            if (_buddy_instance_tag != 0 && _buddy_instance_tag < 4)
                throw new ArgumentException("FormatDHKey: The receiver instance tag cannot take a value less than 4");

            int _next_index = 0;
            int _message_length_2 = message.Length;
            _message_length_2 += _message_length_1;

            _message_temp_buffer = new byte[_message_length_2];


            Buffer.BlockCopy(_encoded_otr_version_byte_array, 0, _message_temp_buffer, _next_index, _encoded_otr_version_byte_array.Length);
            _next_index += _encoded_otr_version_byte_array.Length;

            Buffer.BlockCopy(_encoded_dh_key_message_type, 0, _message_temp_buffer, _next_index, _encoded_dh_key_message_type.Length);
            _next_index += _encoded_dh_key_message_type.Length;


            if (_otr_version != OTR_VERSION.VERSION_2)
            {
                _temp_buffer = BitConverter.GetBytes(_buddy_instance_tag);
                Utility.EncodeOTRInt(_temp_buffer, ref _encoded_receiver_instance_tag);



                Buffer.BlockCopy(_encoded_my_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_my_instance_tag.Length);
                _next_index += _encoded_my_instance_tag.Length;

                Buffer.BlockCopy(_encoded_receiver_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_receiver_instance_tag.Length);
                _next_index += _encoded_receiver_instance_tag.Length;


            }


            Buffer.BlockCopy(message, 0, _message_temp_buffer, _next_index, message.Length);


            return _message_temp_buffer;




        }
        public byte[] FormatRevealSig(byte[] message)
        {
            if (message == null || message.Length < 1)
                throw new ArgumentException("FormatRevealSig: The OTR Message byte array cannot be null/empty");

            if (_buddy_instance_tag != 0 && _buddy_instance_tag < 4)
                throw new ArgumentException("FormatRevealSig: The receiver instance tag cannot take a value less than 4");


            int _next_index = 0;
            int _message_length_2 = message.Length;
            _message_length_2 += _message_length_1;

            _message_temp_buffer = new byte[_message_length_2];


            Buffer.BlockCopy(_encoded_otr_version_byte_array, 0, _message_temp_buffer, _next_index, _encoded_otr_version_byte_array.Length);
            _next_index += _encoded_otr_version_byte_array.Length;



            Buffer.BlockCopy(_encoded_reveal_message_type, 0, _message_temp_buffer, _next_index, _encoded_reveal_message_type.Length);
            _next_index += _encoded_reveal_message_type.Length;




            if (_otr_version != OTR_VERSION.VERSION_2)
            {


                Buffer.BlockCopy(_encoded_my_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_my_instance_tag.Length);
                _next_index += _encoded_my_instance_tag.Length;


                _temp_buffer = BitConverter.GetBytes(_buddy_instance_tag);
                Utility.EncodeOTRInt(_temp_buffer, ref _encoded_receiver_instance_tag);


                Buffer.BlockCopy(_encoded_receiver_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_receiver_instance_tag.Length);
                _next_index += _encoded_receiver_instance_tag.Length;


            }





            Buffer.BlockCopy(message, 0, _message_temp_buffer, _next_index, message.Length);



            return _message_temp_buffer;


        }
        public byte[] FormatSignature(byte[] message)
        {

            if (message == null || message.Length < 1)
                throw new ArgumentException("FormatSignature: The OTR Message byte array cannot be null/empty");

            if (_buddy_instance_tag != 0 && _buddy_instance_tag < 4)
                throw new ArgumentException("FormatSignature: The receiver instance tag cannot take a value less than 4");



            int _next_index = 0;
            int _message_length_2 = message.Length;
            _message_length_2 += _message_length_1;

            _message_temp_buffer = new byte[_message_length_2];


            Buffer.BlockCopy(_encoded_otr_version_byte_array, 0, _message_temp_buffer, _next_index, _encoded_otr_version_byte_array.Length);
            _next_index += _encoded_otr_version_byte_array.Length;



            Buffer.BlockCopy(_encoded_signature_message_type, 0, _message_temp_buffer, _next_index, _encoded_signature_message_type.Length);
            _next_index += _encoded_signature_message_type.Length;




            if (_otr_version != OTR_VERSION.VERSION_2)
            {


                Buffer.BlockCopy(_encoded_my_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_my_instance_tag.Length);
                _next_index += _encoded_my_instance_tag.Length;


                _temp_buffer = BitConverter.GetBytes(_buddy_instance_tag);
                Utility.EncodeOTRInt(_temp_buffer, ref _encoded_receiver_instance_tag);


                Buffer.BlockCopy(_encoded_receiver_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_receiver_instance_tag.Length);
                _next_index += _encoded_receiver_instance_tag.Length;


            }



            Buffer.BlockCopy(message, 0, _message_temp_buffer, _next_index, message.Length);



            return _message_temp_buffer;

        }
        public byte[] FormatData(byte[] message, byte[] old_mac_keys, byte[] sending_mac_key)
        {
            if (message == null || message.Length < 1)
                throw new ArgumentException("FormatData: The OTR Message byte array cannot be null/empty");

            if (_buddy_instance_tag != 0 && _buddy_instance_tag < 4)
                throw new ArgumentException("FormatData: The receiver instance tag cannot take a value less than 4");

            int _next_index = 0;            
            int _message_length_2 = message.Length;
            byte[] _encoded_mac_key_byte_array = null;

            _message_length_2 += _message_length_1 + _encoded_flag.Length;

            _message_temp_buffer = new byte[_message_length_2];


            if (old_mac_keys != null && old_mac_keys.Length > 0)
                Utility.EncodeOTRDataBE(old_mac_keys, ref _encoded_mac_key_byte_array);
            else
                _encoded_mac_key_byte_array = new byte[4];

                         


            Buffer.BlockCopy(_encoded_otr_version_byte_array, 0, _message_temp_buffer, _next_index, _encoded_otr_version_byte_array.Length);
            _next_index += _encoded_otr_version_byte_array.Length;

            Buffer.BlockCopy(_encoded_data_message_type, 0, _message_temp_buffer, _next_index, _encoded_data_message_type.Length);
            _next_index += _encoded_data_message_type.Length;


            if (_otr_version != OTR_VERSION.VERSION_2)
            {
                _temp_buffer = BitConverter.GetBytes(_buddy_instance_tag);
                Utility.EncodeOTRInt(_temp_buffer, ref _encoded_receiver_instance_tag);



                Buffer.BlockCopy(_encoded_my_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_my_instance_tag.Length);
                _next_index += _encoded_my_instance_tag.Length;

                Buffer.BlockCopy(_encoded_receiver_instance_tag, 0, _message_temp_buffer, _next_index, _encoded_receiver_instance_tag.Length);
                _next_index += _encoded_receiver_instance_tag.Length;


            }

            Buffer.BlockCopy(_encoded_flag, 0, _message_temp_buffer, _next_index, _encoded_flag.Length);
            _next_index += _encoded_flag.Length;


            Buffer.BlockCopy(message, 0, _message_temp_buffer, _next_index, message.Length);

            _temp_buffer_2 = Utility.SHA1GetKeyedHash(sending_mac_key, _message_temp_buffer);
            byte[] _message_data_hash = null;


            Utility.EncodeOTRMacBE(_temp_buffer_2, ref _message_data_hash);


           _temp_buffer = new byte[_message_temp_buffer.Length + OTRConstants.TYPE_LEN_MAC + _encoded_mac_key_byte_array.Length];

            _next_index = 0;

            Buffer.BlockCopy(_message_temp_buffer, 0, _temp_buffer, _next_index, _message_temp_buffer.Length);
            _next_index += _message_temp_buffer.Length;

            

            Buffer.BlockCopy(_message_data_hash, 0, _temp_buffer, _next_index, _message_data_hash.Length);
            _next_index += _message_data_hash.Length;


            if (old_mac_keys != null && old_mac_keys.Length > 0)
             Buffer.BlockCopy(_encoded_mac_key_byte_array, 0, _temp_buffer, _next_index, _encoded_mac_key_byte_array.Length);



            return _temp_buffer;






        }

        #endregion

        #region Extract message functions

        public OTRMessage ExtractMessage(byte[] in_message_byte_array)
        {
            int _next_index = 0;
            _otr_message = null;
            _temp_buffer = null;
            _message_type = OTR_MESSAGE_TYPE.INVALID;


            //get protocol version


            _next_index = Utility.DecodeShortFromBytes(in_message_byte_array, _next_index, ref _temp_buffer_2);
            OTR_VERSION _otr_version = Utility.GetOTRVersion(_temp_buffer_2);

            if (_otr_version == OTR_VERSION.INVALID)
                throw new ArgumentException("ExtractMessage:OTR version is invalid");



            _otr_message = new OTRMessage();

            _otr_message.SetProtocolVersion(_otr_version);



            // get message type

            _temp_buffer_2 = _temp_buffer = null;
            _next_index = Utility.DecodeByteFromBytes(in_message_byte_array, _next_index, ref _temp_buffer_2);
            _message_type = GetMessageType(_temp_buffer_2[0]);


            if (_message_type == OTR_MESSAGE_TYPE.INVALID)
                throw new ArgumentException("ExtractMessage:OTR message type is invalid");



            _otr_message.SetMessageType(_message_type);


            //get instance tags
            if (_otr_version != OTR_VERSION.VERSION_2)
            {
                _temp_buffer_2 = _temp_buffer = null;
                _next_index = Utility.DecodeIntFromBytes(in_message_byte_array, _next_index, ref _temp_buffer_2);
                _otr_message.SetSenderInstanceTag(_temp_buffer_2);


                if (_otr_message.GetSenderInstanceTag() < 4)
                    throw new ArgumentException("ExtractMessage:The Sender's instance tag cannot be less than 4");


                if (_buddy_instance_tag == 0)
                    _buddy_instance_tag = _otr_message.GetSenderInstanceTag();


                if (_buddy_instance_tag != 0 && _otr_message.GetSenderInstanceTag() != _buddy_instance_tag)
                    throw new ArgumentException("ExtractMessage:The Sender's instance tag is invalid");





                _temp_buffer_2 = _temp_buffer = null;
                _next_index = Utility.DecodeIntFromBytes(in_message_byte_array, _next_index, ref _temp_buffer_2);

                _otr_message.SetReceiverInstanceTag(_temp_buffer_2);






            }





            if (_message_type == OTR_MESSAGE_TYPE.DATA)
                return ExtractData(in_message_byte_array, _next_index);
            else if (_message_type == OTR_MESSAGE_TYPE.DH_COMMIT)
                return ExtractDHCommit(in_message_byte_array, _next_index);
            else if (_message_type == OTR_MESSAGE_TYPE.DH_KEY)
                return ExtractDHKey(in_message_byte_array, _next_index);
            else if (_message_type == OTR_MESSAGE_TYPE.REVEAL_SIGNATURE)
                return ExtractRevealSig(in_message_byte_array, _next_index);
            else if (_message_type == OTR_MESSAGE_TYPE.SIGNATURE)
                return ExtractSignature(in_message_byte_array, _next_index);



            return null;


        }
        private OTRMessage ExtractDHCommit(byte[] in_message_byte_array, int next_index)
        {

            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            Utility.DecodeDataFromBytesBE(_temp_buffer, 0, ref _temp_buffer_2);
            _otr_message.SetEncryptedGxMpi(_temp_buffer_2);


            _temp_buffer_2 = _temp_buffer = null;
            Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            Utility.DecodeDataFromBytesBE(_temp_buffer, 0, ref _temp_buffer_2);
            _otr_message.SetHashedGxMpi(_temp_buffer_2);


            return _otr_message;


        }
        private OTRMessage ExtractDHKey(byte[] in_message_byte_array, int next_index)
        {

            if (_otr_message.GetProtocolVersion() != OTR_VERSION.VERSION_2 && _otr_message.GetReceiverInstanceTag() != _my_instance_tag)
                throw new ArgumentException("ExtractDHKey:The Receiver's instance tag is invalid");


            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleMpiFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            _otr_message.SetGxMpi(_temp_buffer);

            return _otr_message;
        }
        private OTRMessage ExtractRevealSig(byte[] in_message_byte_array, int next_index)
        {
            if (_otr_message.GetProtocolVersion() != OTR_VERSION.VERSION_2 && _otr_message.GetReceiverInstanceTag() != _my_instance_tag)
                throw new ArgumentException("ExtractRevealSig:The Receiver's instance tag is invalid");



            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            Utility.DecodeDataFromBytesBE(_temp_buffer, 0, ref _temp_buffer_2);
            _otr_message.SetRevealedKey(_temp_buffer_2);



            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            _otr_message.SetEncodedEncryptedSignature(_temp_buffer);



            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeMacFromBytesBE(in_message_byte_array, next_index, ref _temp_buffer);



            _otr_message.SetMacDSignature(_temp_buffer);




            return _otr_message;

        }
        private OTRMessage ExtractSignature(byte[] in_message_byte_array, int next_index)
        {
            if (_otr_message.GetProtocolVersion() != OTR_VERSION.VERSION_2 && _otr_message.GetReceiverInstanceTag() != _my_instance_tag)
                throw new ArgumentException("ExtractSignature:The Receiver's instance tag is invalid");




            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            _otr_message.SetEncodedEncryptedSignature(_temp_buffer);


            _temp_buffer = new byte[20];


            Buffer.BlockCopy(in_message_byte_array, next_index, _temp_buffer, 0, _temp_buffer.Length);


            _otr_message.SetMacDSignature(_temp_buffer);


            return _otr_message;

        }
        private OTRMessage ExtractData(byte[] in_message_byte_array, int next_index)
        {


            if (_otr_message.GetProtocolVersion() != OTR_VERSION.VERSION_2 && _otr_message.GetReceiverInstanceTag() != _my_instance_tag)
                throw new ArgumentException("ExtractData:The Receiver's instance tag is invalid");


            /* Get flag*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeByteFromBytes(in_message_byte_array, next_index, ref _temp_buffer_2);
            _otr_message.SetFlags(_temp_buffer_2[0]);


            /* Get Sender's Key ID*/

            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeIntFromBytes(in_message_byte_array, next_index, ref _temp_buffer_2);
            _otr_message.SetSenderKeyId(_temp_buffer_2);


            /* Get Recipaint's Key ID*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeIntFromBytes(in_message_byte_array, next_index, ref _temp_buffer_2);
            _otr_message.SetRecipientKeyId(_temp_buffer_2);

            /* Get Sender's MPI encoded public Key ID*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleMpiFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            _otr_message.SetNextDHPublicKeyMpi(_temp_buffer);

            /* Get Counter top half*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeCtrFromBytes(in_message_byte_array, next_index, ref _temp_buffer_2);
            _otr_message.SetCounterTopHalf(_temp_buffer_2);


            /* Get Encrypted data*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
            Utility.DecodeDataFromBytesBE(_temp_buffer, 0, ref _temp_buffer_2);
            _otr_message.SetEncryptedData(_temp_buffer_2);


            /* Get the bytes to be authenticated*/
            _temp_buffer = new byte[next_index];
            Buffer.BlockCopy(in_message_byte_array, 0, _temp_buffer, 0, _temp_buffer.Length);
            _otr_message.SetBytesToAuthenticate(_temp_buffer);



            /* Get Authenticator MAC*/
            _temp_buffer_2 = _temp_buffer = null;
            next_index = Utility.DecodeMacFromBytesBE(in_message_byte_array, next_index, ref _temp_buffer_2);
            _otr_message.SetAuthenticationMAC(_temp_buffer_2);



            /* Get old MAC keys: There are no mac bytes if in_message_byte_array.Length - next_index = 4 */
            // /*                            
            if (next_index > -1 && in_message_byte_array.Length - next_index > 4)
            {
                _temp_buffer_2 = _temp_buffer = null;
                next_index = Utility.DecoupleDataFromBytes(in_message_byte_array, next_index, ref _temp_buffer);
                Utility.DecodeDataFromBytes(_temp_buffer, 0, ref _temp_buffer_2);
                _otr_message.SetOldMacKeys(_temp_buffer_2);


            }//*/

            






            return _otr_message;
        }

        #endregion


        #region Utilities

        private OTR_MESSAGE_TYPE GetMessageType(byte message_type_byte)
        {
            if (message_type_byte == OTRConstants.MESSAGE_TYPE_DH_COMMIT)
                return OTR_MESSAGE_TYPE.DH_COMMIT;

            if (message_type_byte == OTRConstants.MESSAGE_TYPE_DH_KEY)
                return OTR_MESSAGE_TYPE.DH_KEY;

            if (message_type_byte == OTRConstants.MESSAGE_TYPE_REVEAL_SIGNATURE)
                return OTR_MESSAGE_TYPE.REVEAL_SIGNATURE;

            if (message_type_byte == OTRConstants.MESSAGE_TYPE_SIGNATURE)
                return OTR_MESSAGE_TYPE.SIGNATURE;


            if (message_type_byte == OTRConstants.MESSAGE_TYPE_DATA)
                return OTR_MESSAGE_TYPE.DATA;


            return OTR_MESSAGE_TYPE.INVALID;

        }
        public static OTR_VERSION GetMessageOTRVersion(byte[] in_message_byte_array)
        {

            byte[] _temp_buffer_2 = null;

            Utility.DecodeShortFromBytes(in_message_byte_array, 0, ref _temp_buffer_2);
            return Utility.GetOTRVersion(_temp_buffer_2);

        }
        public UInt32 GetBuddyIntanceTag()
        {
            if (_otr_version != OTR_VERSION.VERSION_2)
                return _buddy_instance_tag;

            return 0;

        }
        public UInt32 GetMyIntanceTag()
        {
            if (_otr_version != OTR_VERSION.VERSION_2)
                return _my_instance_tag;


            return 0;

        }


        #endregion


    }
}
