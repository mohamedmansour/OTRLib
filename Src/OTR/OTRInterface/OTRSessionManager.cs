using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using OTR.Managers;
using OTR.Utilities;
using System.IO;

namespace OTR.Interface
{
   public class OTRSessionManager
    {
       private Dictionary<string, OTRSession> _otr_session_register;
        

        string _my_unique_id = string.Empty;
        public OTRSessionManager(string my_unique_id)
        {
               if (string.IsNullOrEmpty(my_unique_id))
               throw new ArgumentException("OTRSessionManager:My uique ID cannot be null/empty");

               _my_unique_id = my_unique_id;

              _otr_session_register = new Dictionary<string, OTRSession>();
              


        }


        #region OTR Session management functions

        public void CreateOTRSession(string my_buddy_unique_id)
        {

            CreateOTRSession(my_buddy_unique_id, false);

        }
        public void CreateOTRSession(string my_buddy_unique_id, bool debug_mode)
        {

            if (string.IsNullOrEmpty(my_buddy_unique_id))
            throw new ArgumentException("CreateOTRSession:My buddy uique ID cannot be null/empty");

            
            if (IsSessionRegistered(my_buddy_unique_id) == true)
                throw new ArgumentException("CreateOTRSession: A session with this unique ID already exists");

            OTRSession _session_object = new OTRSession(_my_unique_id, my_buddy_unique_id, debug_mode);
            
            _session_object.OnOTREvent += new OTREventHandler(OTRSessionEventHandler);           

            _otr_session_register.Add(my_buddy_unique_id, _session_object);

           
        }

        public void CreateOTRSession(string my_buddy_unique_id, DSAKeyParams dsa_key_hex_string, bool debug_mode)
        {

            if (string.IsNullOrEmpty(my_buddy_unique_id))
            throw new ArgumentException("CreateOTRSession:My buddy uique ID cannot be null/empty");

            if (dsa_key_hex_string == null)
            throw new ArgumentException("CreateOTRSession:The DSA key parameter Hex string object cannot be null");

            
            if (IsSessionRegistered(my_buddy_unique_id) == true)
            throw new InvalidDataException("CreateOTRSession: A session with this unique ID already exists");

            OTRSession _session_object = new OTRSession(_my_unique_id, my_buddy_unique_id, dsa_key_hex_string, debug_mode);

            _session_object.OnOTREvent += new OTREventHandler(OTRSessionEventHandler);

            _otr_session_register.Add(my_buddy_unique_id, _session_object);


        }
        public void CreateOTRSession(string my_buddy_unique_id, DSAKeyParams dsa_key_hex_string)
        {

            if (string.IsNullOrEmpty(my_buddy_unique_id))
                throw new ArgumentException("CreateOTRSession:My buddy uique ID cannot be null/empty");

            if (dsa_key_hex_string == null)
              throw new ArgumentException("CreateOTRSession:The DSA key parameter object cannot be null");


            if (IsSessionRegistered(my_buddy_unique_id) == true)
                throw new InvalidDataException("CreateOTRSession: A session with this unique ID already exists");

            OTRSession _session_object = new OTRSession(_my_unique_id, my_buddy_unique_id, dsa_key_hex_string);

            _session_object.OnOTREvent += new OTREventHandler(OTRSessionEventHandler);

            _otr_session_register.Add(my_buddy_unique_id, _session_object);


        }
                     
       
        public void CloseAllSessions()
        {

            List<string> _keys = _otr_session_register.Keys.ToList();

            foreach (string _key in _keys)
            {

                _otr_session_register[_key].EndOTRSession();

            }



        }
        public void CloseSession(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return;

            _otr_session_register[my_buddy_unique_id].EndOTRSession();

            DeleteOTRSession(my_buddy_unique_id);



        }
        public void RequestOTRSession(string my_buddy_unique_id, string otr_version)
        {


            if (string.IsNullOrEmpty(otr_version) == true)
                throw new ArgumentException("RequestOTRSession: The OTR version string cannot be null/empty");


            if (IsSessionRegistered(my_buddy_unique_id) == false)
             throw new ArgumentException("RequestOTRSession: my buddy unique id does not exist");

            OTR_VERSION _otr_version = Utility.GetOTRVersion(otr_version);


            if (_otr_version == OTR_VERSION.INVALID)
                throw new ArgumentException("RequestOTRSession: OTR version is invalid");

            string _otr_version_string = string.Empty;

            if (_otr_version == OTR_VERSION.VERSION_2)
                _otr_version_string = OTRConstants.OTR_VERSION_2;
            else if (_otr_version == OTR_VERSION.VERSION_3)
                _otr_version_string = OTRConstants.OTR_VERSION_3;
           
            OTREventArgs _event_args = new OTREventArgs();
            _event_args.SetMessage(_otr_version_string);
            _event_args.SetOTREvent(OTR_EVENT.SEND);
            _event_args.SetSessionID(my_buddy_unique_id);

            OnOTREvent(this, _event_args);

        }
        public bool IsSessionValid(string my_buddy_unique_id)
        {
            return IsSessionRegistered(my_buddy_unique_id);

        }

        #endregion

        #region Message Processing functions
        public void ProcessOTRMessage(string my_buddy_unique_id, string otr_message_string)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
            throw new ArgumentException("ProcessOTRMessage: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(otr_message_string))
                return;

            
            if (Utility.IsStringExist(otr_message_string, OTRConstants.OTR_VERSION_1_2) == true 
             || Utility.IsStringExist(otr_message_string, OTRConstants.OTR_VERSION_2) == true
             || Utility.IsStringExist(otr_message_string, OTRConstants.OTR_VERSION_1_AND_2) == true )
            {

                _otr_session_register[my_buddy_unique_id].StartOTRSession(OTRConstants.OTR_VERSION_2);
                return;
            }

            if (Utility.IsStringExist(otr_message_string, OTRConstants.OTR_VERSION_2_AND_3) == true
            || Utility.IsStringExist(otr_message_string, OTRConstants.OTR_VERSION_3) == true)
            {
                _otr_session_register[my_buddy_unique_id].StartOTRSession(OTRConstants.OTR_VERSION_3);
                return;
            }
            
             _otr_session_register[my_buddy_unique_id].ProcessMessage(otr_message_string);
            
        }

        public void EncryptMessage(string my_buddy_unique_id,string message_string)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
             throw new ArgumentException("EncryptMessage: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(message_string))
                return;

            _otr_session_register[my_buddy_unique_id].EncryptMessage(message_string);


        }
        public void EncryptMessage(string my_buddy_unique_id,string message_string, UInt16 padding_length_bytes)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("EncryptMessage: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(message_string))
                return;

            _otr_session_register[my_buddy_unique_id].EncryptMessage(message_string, padding_length_bytes);



        }
        public void EncryptMessage(string my_buddy_unique_id, string message_string, bool start_smp, UInt16 padding_length_bytes)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("EncryptMessage: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(message_string))
                return;

            _otr_session_register[my_buddy_unique_id].EncryptMessage(message_string, start_smp, padding_length_bytes);

        }
        public void EncryptMessage(string my_buddy_unique_id, bool start_smp, UInt16 padding_length_bytes)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("EncryptMessage: my buddy unique id does not exist");

           

            _otr_session_register[my_buddy_unique_id].EncryptMessage(start_smp, padding_length_bytes);

        }
        public void EncryptMessage(string my_buddy_unique_id, string message_string, bool start_smp)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("EncryptMessage: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(message_string))
                return;

            _otr_session_register[my_buddy_unique_id].EncryptMessage(message_string, start_smp);

        }
        public void EncryptFragments(string my_buddy_unique_id, string message_string, UInt16 max_fragement_length)
        {


            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("EncryptFragments: my buddy unique id does not exist");

            if (string.IsNullOrEmpty(message_string))
                return;

            _otr_session_register[my_buddy_unique_id].EncryptFragments(message_string, max_fragement_length);

        }
        public void StartSMP(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("StartSMP: my buddy unique id does not exist");


            _otr_session_register[my_buddy_unique_id].StartSMP();


        }
        
       
       
        public void AbortSMP(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("AbortSMP: my buddy unique id does not exist");


            _otr_session_register[my_buddy_unique_id].AbortSMP();
        }
        public void SendHeartBeat(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
            throw new ArgumentException("SendHeartBeat: my buddy unique id does not exist");


            _otr_session_register[my_buddy_unique_id].SendHeartBeat();
        }
        public void RequestExtraKeyUse(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
             throw new ArgumentException("RequestExtraKeyUse: my buddy unique id does not exist");


            _otr_session_register[my_buddy_unique_id].RequestExtraKeyUse();
        }
        
        #endregion

        #region Other functions

        public OTR_MESSAGE_STATE GetSessionMessageState(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return OTR_MESSAGE_STATE.INVALID;
            

            return _otr_session_register[my_buddy_unique_id].GetMessageState();

        }
        private bool DeleteOTRSession(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
            return false;


          return _otr_session_register.Remove(my_buddy_unique_id);


        }
                
        private bool IsSessionRegistered(string my_buddy_unique_id)
        {

            return _otr_session_register.ContainsKey(my_buddy_unique_id);

        }

        private void OTRSessionEventHandler(object source, OTREventArgs e)
        {
            try
            {
                OnOTREvent(this, e);
                
                
                if (/*e.GetOTREvent() == OTR_EVENT.ERROR ||*/ e.GetOTREvent() == OTR_EVENT.CLOSED)
                {
                    DeleteOTRSession(e.GetSessionID());

                }

            }
            catch
            {



            }

        }

        public static List<string> GetSupportedOTRVersionList()
        {
            return OTRConstants.VERSION_LIST();
        }
       
       
        public DSAKeyParams GetSessionDSAHexParams(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return null;


            return _otr_session_register[my_buddy_unique_id].GetMyDSAKeyHexParams();
        }

        public string GetSessionDSAFingerPrint(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return string.Empty;

            return _otr_session_register[my_buddy_unique_id].GetMyDSAFingerPrint();

        }
        public string GetMyBuddyFingerPrint(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
             return string.Empty;

            return _otr_session_register[my_buddy_unique_id].GetMyBuddyDSAFingerPrint();

        }

        public byte [] GetExtraSymmetricKey(string my_buddy_unique_id)
        {

            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return null;

            return _otr_session_register[my_buddy_unique_id].GetExtraSymmetricKey();

        }
        public void SetSMPUserSecret(string my_buddy_unique_id,string secret)
        {
            if (string.IsNullOrEmpty(secret) == true)
           throw new ArgumentException("SetSMPSecret: The secret string cannot be null/empty");

            if (IsSessionRegistered(my_buddy_unique_id) == false)
            throw new ArgumentException("SetSMPSecret: my buddy unique id does not exist");

            _otr_session_register[my_buddy_unique_id].SetSMPUserSpecSecret(secret);

        }

        public string GetSMPUserSecret(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                return string.Empty;


           return _otr_session_register[my_buddy_unique_id].GetSMPUserSpecSecret();


        }
        public void SetSMPFragLength(string my_buddy_unique_id, UInt16 max_fragement_length)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
                throw new ArgumentException("SetSMPFragLength: my buddy unique id does not exist");

            _otr_session_register[my_buddy_unique_id].SetSMPFragLength(max_fragement_length);

        }
        public UInt16 GetSMPFragLength(string my_buddy_unique_id)
        {
            if (IsSessionRegistered(my_buddy_unique_id) == false)
             throw new ArgumentException("GetSMPFragLength: my buddy unique id does not exist");

            return _otr_session_register[my_buddy_unique_id].GetSMPFragLength();

        }

        #endregion
       
        #region Event Function

        public event OTREventHandler OnOTREvent;

        #endregion

      
    
    
    }


   

}
