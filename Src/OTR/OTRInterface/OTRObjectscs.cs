using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


using Org.BouncyCastle.Math;


namespace OTR.Interface
{


    class OTRObjectscs
    {



    }
  
    public class DSAKeyParams
    {

        BigInteger _p = null;
        BigInteger _q = null;
        BigInteger _g = null;
        BigInteger _x = null;


        string _p_hex = string.Empty;
        string _q_hex = string.Empty;
        string _g_hex = string.Empty;
        string _x_hex = string.Empty;


        public DSAKeyParams(byte[] p, byte[] q, byte[] g, byte[] x)
        {
            if (p == null || p.Length < 1)
                throw new ArgumentException("DSAKeyBytes: The p parameter byte array cannot be null/empty");

            if (q == null || q.Length < 1)
                throw new ArgumentException("DSAKeyBytes: The q parameter byte array cannot be null/empty");

            if (g == null || g.Length < 1)
                throw new ArgumentException("DSAKeyBytes: The G parameter byte array cannot be null/empty");

            if (x == null || x.Length < 1)
                throw new ArgumentException("DSAKeyBytes: The x parameter byte array cannot be null/empty");



            _p = new BigInteger(p);
            _q = new BigInteger(q);
            _g = new BigInteger(g);
            _x = new BigInteger(x);


        }


        public DSAKeyParams(string p, string q, string g, string x)
        {
            if (string.IsNullOrEmpty(p) == true)
                throw new ArgumentException("DSAKeyHexStrings: The p parameter hex string cannot be null/empty");

            if (string.IsNullOrEmpty(q) == true)
                throw new ArgumentException("DSAKeyHexStrings: The q parameter hex string cannot be null/empty");


            if (string.IsNullOrEmpty(g) == true)
                throw new ArgumentException("DSAKeyHexStrings: The g parameter hex string cannot be null/empty");


            if (string.IsNullOrEmpty(x) == true)
                throw new ArgumentException("DSAKeyHexStrings: The x parameter hex string cannot be null/empty");


                      

            _p = new BigInteger(p, 16);
            _q = new BigInteger(q, 16);
            _g = new BigInteger(g, 16);
            _x = new BigInteger(x, 16);



        }


        public BigInteger GetParamP()
        {
            return _p;
        }
        public BigInteger GetParamQ()
        {
            return _q;
        }
        public BigInteger GetParamG()
        {
            return _g;
        }
        public BigInteger GetParamX()
        {
            return _x;
        }


        public DSAKeyParams(BigInteger p, BigInteger q, BigInteger g, BigInteger x)
        {
            if (p == null)
                throw new ArgumentException("DSAKeyHexStrings:DSA key parameter P cannot be null");

            if (q == null)
                throw new ArgumentException("DSAKeyHexStrings:DSA key parameter Q cannot be null");

            if (g == null)
                throw new ArgumentException("DSAKeyHexStrings:DSA key parameter G cannot be null");

            if (x == null)
                throw new ArgumentException("DSAKeyHexStrings:DSA key parameter X cannot be null");


            _p = p;
            _q = q;
            _g = g;
            _x = x;


            _p_hex = OTR.Utilities.Utility.ByteToHex(p.ToByteArray());

            _q_hex = OTR.Utilities.Utility.ByteToHex(q.ToByteArray());

            _g_hex = OTR.Utilities.Utility.ByteToHex(g.ToByteArray());

            _x_hex = OTR.Utilities.Utility.ByteToHex(x.ToByteArray());



        }

        public string GetHexParamP()
        {
            return _p_hex;
        }
        public string GetHexParamQ()
        {
            return _q_hex;
        }
        public string GetHexParamG()
        {
            return _g_hex;
        }
        public string GetHexParamX()
        {
            return _x_hex;
        }


    }
     
    
    public enum OTR_EVENT
    {
        ERROR,
        DEBUG,
        MESSAGE,
        EXTRA_KEY_REQUEST,
        SEND,
        READY,
        CLOSED,
        SMP_MESSAGE, 
        HEART_BEAT,
        INVALID


    }

    public enum OTR_SMP_EVENT
    {
        SEND,
        FAILED,
        SUCCEEDED,
        ABORT,
        INVALID

    }
   
    
    #region OTR Event Delegates
         
    public delegate void OTREventHandler(object source, OTREventArgs e);

    public class OTREventArgs : EventArgs
    {
        private string _message = string.Empty;
        private string _error_message         = string.Empty;
        private string _error_message_verbose = string.Empty;
        private string _session_id = string.Empty;
        private byte[] _old_mac_keys = null;

        private OTR_EVENT _otr_event = OTR_EVENT.INVALID;
        private OTR_SMP_EVENT _smp_event = OTR_SMP_EVENT.INVALID;


        public void SetOldMacKeys(byte[] old_mac_keys)
        {

            if (old_mac_keys == null || old_mac_keys.Length < 1)
                return;

            _old_mac_keys = new byte[old_mac_keys.Length];

            Buffer.BlockCopy(old_mac_keys, 0, _old_mac_keys, 0, _old_mac_keys.Length);


        }

        public byte[] GetOldMacKeys()
        {
            return _old_mac_keys;

        }
      
        public void SetSessionID(string session_id)
        {
            if (string.IsNullOrEmpty(session_id))
                return;

            _session_id = session_id;
        }

        public string GetSessionID()
        {
            return _session_id;
        }
        
        public void SetMessage(string message)
        {
            if (string.IsNullOrEmpty(message))
                return;

            _message = message;
        }

        public string GetMessage()
        {
            return _message;
        }

        public void SetErrorMessage(string error_message)
        {
            if (string.IsNullOrEmpty(error_message))
                return;

            _error_message = error_message;
        }
        public string GetErrorMessage()
        {
            return _error_message;
        }
        
        public void SetErrorVerbose(string error_message_verbose)
        {
            if (string.IsNullOrEmpty(error_message_verbose))
                return;

            _error_message_verbose = error_message_verbose;
        }
        public string GetErrorVerbose()
        {
            return _error_message_verbose;
        }

        public void SetOTREvent(OTR_EVENT otr_event)
        {
            _otr_event = otr_event;
        }

        public OTR_EVENT GetOTREvent()
        {
            return _otr_event;
        }


        public void SetSMPEvent(OTR_SMP_EVENT smp_event)
        {
            _smp_event = smp_event;
        }

        public OTR_SMP_EVENT GetSMPEvent()
        {
            return _smp_event;
        }
        
    }

    #endregion
}
