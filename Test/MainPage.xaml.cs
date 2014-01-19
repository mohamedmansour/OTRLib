using OTR.Interface;
using System;
using Windows.UI.Xaml.Controls;

namespace OTRTest
{
    public sealed partial class MainPage : Page
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

        public MainPage()
        {
            this.InitializeComponent();
            this.SetConvoArray();
            this.InitializeOTR();
        }

        void SetConvoArray()
        {
            _alice_convo_array = new string[3];
            _bob_convo_array = new string[3];

            _alice_convo_array[0] = "What are we doing?";
            _alice_convo_array[1] = "So this is what hacking feels like?";
            _alice_convo_array[2] = "Be nice! That's mean.";

            _bob_convo_array[0] = "Hacking";
            _bob_convo_array[1] = "Huh?";
            _bob_convo_array[2] = "Sure ...";

            _alice_convo_pos = 0;
            _bob_convo_pos = 0;
        }

        private void InitializeOTR()
        {
            _alice_my_buddy_unique_id = _bob_unique_id;
            _bob_my_buddy_unique_id = _alice_unique_id;

            _bob_otr_session_manager = new OTRSessionManager(_bob_unique_id);
            _alice_otr_session_manager = new OTRSessionManager(_alice_unique_id);

            _bob_otr_session_manager.OnOTREvent += new OTREventHandler(OnBobOTRMangerEventHandler);
            _alice_otr_session_manager.OnOTREvent += new OTREventHandler(OnAliceOTRMangerEventHandler);

            _bob_otr_session_manager.CreateOTRSession(_bob_my_buddy_unique_id);
            _alice_otr_session_manager.CreateOTRSession(_alice_my_buddy_unique_id);

            _alice_otr_session_manager.RequestOTRSession(_alice_my_buddy_unique_id, OTRSessionManager.GetSupportedOTRVersionList()[0]);
        }

        private void OnBobOTRMangerEventHandler(object source, OTREventArgs e)
        {

            switch (e.GetOTREvent())
            {
                case OTR_EVENT.MESSAGE:
                    log.Items.Add(String.Format("{0}: {1} \n", e.GetSessionID(), e.GetMessage()));
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
                    log.Items.Add(String.Format("Bob: OTR Error: {0} \n", e.GetErrorMessage()));
                    log.Items.Add(String.Format("Bob: OTR Error Verbose: {0} \n", e.GetErrorVerbose()));
                    break;
                case OTR_EVENT.READY:
                    log.Items.Add(String.Format("Bob: Encrypted OTR session with {0} established \n", e.GetSessionID()));
                    break;
                case OTR_EVENT.DEBUG:
                    log.Items.Add(String.Format("Bob: " + e.GetMessage() + "\n"));
                    break;
                case OTR_EVENT.EXTRA_KEY_REQUEST:
                    break;
                case OTR_EVENT.SMP_MESSAGE:
                    log.Items.Add(String.Format("Bob: " + e.GetMessage() + "\n"));
                    break;
                case OTR_EVENT.CLOSED:
                    log.Items.Add(String.Format("Bob: Encrypted OTR session with {0} closed \n", e.GetSessionID()));
                    break;
            }
        }

        private void OnAliceOTRMangerEventHandler(object source, OTREventArgs e)
        {
            switch (e.GetOTREvent())
            {
                case OTR_EVENT.MESSAGE:
                    log.Items.Add(String.Format("{0}: {1} \n", e.GetSessionID(), e.GetMessage()));
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
                    log.Items.Add(String.Format("Alice: OTR Error: {0} \n", e.GetErrorMessage()));
                    log.Items.Add(String.Format("Alice: OTR Error Verbose: {0} \n", e.GetErrorVerbose()));
                    break;
                case OTR_EVENT.READY:
                    log.Items.Add(String.Format("Alice: Encrypted OTR session with {0} established \n", e.GetSessionID()));
                    _alice_convo_pos++;
                    _alice_otr_session_manager.EncryptMessage(_alice_my_buddy_unique_id, _alice_convo_array[_alice_convo_pos - 1]);
                    break;
                case OTR_EVENT.DEBUG:
                    log.Items.Add(String.Format("Alice: " + e.GetMessage() + "\n"));
                    break;
                case OTR_EVENT.EXTRA_KEY_REQUEST:
                    break;
                case OTR_EVENT.SMP_MESSAGE:
                    log.Items.Add(String.Format("Alice: " + e.GetMessage() + "\n"));
                    break;
                case OTR_EVENT.CLOSED:
                    log.Items.Add(String.Format("Alice: Encrypted OTR session with {0} closed \n", e.GetSessionID()));
                    break;
            }
        }

        private void SendDataOnNetwork(string my_unique_id, string otr_data)
        {
            if (my_unique_id == _alice_unique_id)
            {
                log.Items.Add(String.Format("Encrypted data: {0}\n ", otr_data));
                _bob_otr_session_manager.ProcessOTRMessage(_bob_my_buddy_unique_id, otr_data);
            }
            else if (my_unique_id == _bob_unique_id)
            {
                _alice_otr_session_manager.ProcessOTRMessage(_alice_my_buddy_unique_id, otr_data);
            }
        }
    }
}
