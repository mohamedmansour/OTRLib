using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using OTR.Interface;

namespace OTRLibTest
{
    class OTRTest
    {
        string[] _alice_convo_array = null;
        string[] _bob_convo_array = null;
        int _alice_convo_pos = 0;
        int _bob_convo_pos = 0;

        OTRSessionManager _bob_otr_session_manager = null;
        OTRSessionManager _alice_otr_session_manager = null;


        string _bob_unique_id = "bob";
        string _alice_unique_id = "alice";

        string _alice_my_buddy_unique_id = string.Empty;
        string _bob_my_buddy_unique_id = string.Empty;


        DSAKeyParams _alice_des_key_object = null;
        DSAKeyParams _bob_des_key_object = null;

         void SetConvoArray()
        {

            http://www.damnyouautocorrect.com/

            _alice_convo_array = new string[3];
            _bob_convo_array = new string[3];

            _alice_convo_array[0] = "Do I look like a cow?";
            _alice_convo_array[1] = ":( great";
            _alice_convo_array[2] = "Be nice! That's mean.";

            _bob_convo_array[0] = "Moo";
            _bob_convo_array[1] = "Mooooo";
            _bob_convo_array[2] = "Omfg! Those were the worst autocorrects EVER!!! I said Noo, I swear to god.";

            _alice_convo_pos = 0;
            _bob_convo_pos = 0;

                       

          
           


        }

        void SetDSAPublicKeys()
        {
            string _dsa_key_1_p = "00e24d61e1c20661e7514e594cc959859c62eeade72893a4772d3efd246abeb5a2848fb5e4b05a9c5b4edb5b67e53cdeb8337a8e4e44b26a6c1927be024695c83d";
            string _dsa_key_1_q = "00c873b36de07d9ebea48ee96bcc259b94304c65d9";
            string _dsa_key_1_g = "008028acddbd4e51ba344c7e5bacdaf68ecfce35beead41cf12b3d1093c479c24148d817645a4123604774a8824be2a47e19016e1b4247ea40413cf478fff9009c";
            string _dsa_key_1_x = "333715606eebd0925e79da44e02bdfd0cdba5a";

            string _dsa_key_2_p = "00e5cc7a4d6cd189b8d176086aec944c2db1e7f8bf13e6b20a3456d8bb9a33d7bb8960de8d1eb4fdf1fbd4ccbb3ecd7ca927169247d2cabff935a70ddbccae6d69";
            string _dsa_key_2_q = "00c9fefa6732d392a57ecebdf6e990887ea52d2835";
            string _dsa_key_2_g = "0e9135dc3bd3479de6aae872781ad95703a107915689e655f3ddb2bf99c79af5cec4df5bafe5e502ceb0ca26bac67eefcace2e9f42dc972af4ab0033eeeb583e";
            string _dsa_key_2_x = "00a150c9bec477f9713768f6fc1dfd784702c4ffcd";


           


            _alice_des_key_object = new DSAKeyParams(_dsa_key_1_p, _dsa_key_1_q, _dsa_key_1_g, _dsa_key_1_x);
            _bob_des_key_object = new DSAKeyParams(_dsa_key_2_p, _dsa_key_2_q, _dsa_key_2_g, _dsa_key_2_x);


        }

        public void RunOTRTest()
        {

            SetConvoArray();
            SetDSAPublicKeys();


            _alice_my_buddy_unique_id  = _bob_unique_id;
            _bob_my_buddy_unique_id    = _alice_unique_id;


            _bob_otr_session_manager = new OTRSessionManager(_bob_unique_id);
            _alice_otr_session_manager = new OTRSessionManager(_alice_unique_id);

            _bob_otr_session_manager.OnOTREvent += new OTREventHandler(OnBobOTRMangerEventHandler);
            _alice_otr_session_manager.OnOTREvent += new OTREventHandler(OnAliceOTRMangerEventHandler);


            /*
            // *Alice and Bob want to use their DSA keys
            _bob_otr_session_manager.CreateOTRSession(_bob_my_buddy_unique_id, _bob_des_key_object);
            _alice_otr_session_manager.CreateOTRSession(_alice_my_buddy_unique_id, _alice_des_key_object);
            // */


            

            /*
            Want to run in Debug mode?*/
            /*
           _bob_otr_session_manager.CreateOTRSession(_bob_my_buddy_unique_id, true);
           _alice_otr_session_manager.CreateOTRSession(_alice_my_buddy_unique_id, true);

            //*/


            /* Set the SMP fragemnt length  */

            /*
           _alice_otr_session_manager.SetSMPFragLength(_alice_my_buddy_unique_id, 100);
           _bob_otr_session_manager.SetSMPFragLength(_bob_my_buddy_unique_id, 100);
             
            // */ 


            /* Alice and Bob do not have DSA keys. So OTR creates random keys for them  */
            
           // /*

             _bob_otr_session_manager.CreateOTRSession(_bob_my_buddy_unique_id);
            _alice_otr_session_manager.CreateOTRSession(_alice_my_buddy_unique_id);

           // */

           

           
            /*Alice requests an OTR session with Bob  using OTR version 2
             To use version 3 set OTRSessionManager.GetSupportedOTRVersionList()[1]
             * or
             * OTRSessionManager.GetSupportedOTRVersionList()[2]
             */

            _alice_otr_session_manager.RequestOTRSession(_alice_my_buddy_unique_id, OTRSessionManager.GetSupportedOTRVersionList()[0]);



        }
        
        private void OnBobOTRMangerEventHandler(object source, OTREventArgs e)
        {

            switch (e.GetOTREvent())
            {
                case OTR_EVENT.MESSAGE:

                    Console.WriteLine("{0}: {1} \n", e.GetSessionID(), e.GetMessage());
                    
                    if (_bob_convo_pos < _bob_convo_array.Length)
                    {

                        _bob_convo_pos++;
                        _bob_otr_session_manager.EncryptMessage(_bob_my_buddy_unique_id, _bob_convo_array[_bob_convo_pos - 1]);
                    }
                    
                    break;

                case OTR_EVENT.SEND:

                  
                    SendDataOnNetwork(_bob_unique_id, e.GetMessage());

                    break;
                case OTR_EVENT.ERROR:

                    Console.WriteLine("Bob: OTR Error: {0} \n", e.GetErrorMessage());
                    Console.WriteLine("Bob: OTR Error Verbose: {0} \n", e.GetErrorVerbose());

                    break;
                case OTR_EVENT.READY:


                    Console.WriteLine("Bob: Encrypted OTR session with {0} established \n", e.GetSessionID());


                    break;
                case OTR_EVENT.DEBUG:

                    Console.WriteLine("Bob: " + e.GetMessage() + "\n");

                    break;
                case OTR_EVENT.EXTRA_KEY_REQUEST:


                    break;
                case OTR_EVENT.SMP_MESSAGE:


                    Console.WriteLine("Bob: " + e.GetMessage() + "\n");



                    break;
                case OTR_EVENT.CLOSED:



                    Console.WriteLine("Bob: Encrypted OTR session with {0} closed \n", e.GetSessionID());


                    break;

            }

        }

        private void OnAliceOTRMangerEventHandler(object source, OTREventArgs e)
        {

            switch (e.GetOTREvent())
            {
                case OTR_EVENT.MESSAGE:

                    Console.WriteLine("{0}: {1} \n", e.GetSessionID(), e.GetMessage());
                    if (_alice_convo_pos < _alice_convo_array.Length)
                    {
                        _alice_convo_pos++;
                        _alice_otr_session_manager.EncryptMessage(_alice_my_buddy_unique_id, _alice_convo_array[_alice_convo_pos - 1]);
                    }


                    break;

                case OTR_EVENT.SEND:

                  
                    SendDataOnNetwork(_alice_unique_id, e.GetMessage());

                    break;
                case OTR_EVENT.ERROR:

                    Console.WriteLine("Alice: OTR Error: {0} \n", e.GetErrorMessage());
                    Console.WriteLine("Alice: OTR Error Verbose: {0} \n", e.GetErrorVerbose());

                    break;
                case OTR_EVENT.READY:


                    Console.WriteLine("Alice: Encrypted OTR session with {0} established \n", e.GetSessionID());

                                    

                   _alice_convo_pos++;
                    _alice_otr_session_manager.EncryptMessage(_alice_my_buddy_unique_id, _alice_convo_array[_alice_convo_pos - 1]);



                    break;
                case OTR_EVENT.DEBUG:

                    Console.WriteLine("Alice: " + e.GetMessage() + "\n");

                    break;
                case OTR_EVENT.EXTRA_KEY_REQUEST:


                    break;
                case OTR_EVENT.SMP_MESSAGE:


                Console.WriteLine("Alice: " + e.GetMessage() + "\n");



                    break;
                case OTR_EVENT.CLOSED:



                Console.WriteLine("Alice: Encrypted OTR session with {0} closed \n", e.GetSessionID());


                    break;

            }

        }


        private void SendDataOnNetwork(string my_unique_id, string otr_data)
        {
            if (my_unique_id == _alice_unique_id)
          _bob_otr_session_manager.ProcessOTRMessage(_bob_my_buddy_unique_id, otr_data);
           else if (my_unique_id == _bob_unique_id)
           _alice_otr_session_manager.ProcessOTRMessage(_alice_my_buddy_unique_id, otr_data);

        }
    }
}
