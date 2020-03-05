using System;
using System.Net;
using System.Net.Sockets;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Security;
using Lextm.SharpSnmpLib.Messaging;
using System.Reflection;
using System.Windows;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Windows.Media;
using System.Windows.Controls;

namespace SnmpTest
{
    /// <summary>
    /// Interaktionslogik für MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public class OidData
        {
            public string Description { get; set; }
            public string Oid { get; set; }

            public OidData(string _description, string _oid)
            {
                Description = _description;
                Oid = _oid;
            }
        }

        public List<OidData> OidList { get; set; }
        public MainWindow()
        {
            InitializeComponent();
            DataContext = this;

            OidList = new List<OidData>()
            {
                new OidData("Download Speed", "1.3.6.1.4.1.272.4.16.10.1.24.3000000.0"),
                new OidData("Upload Speed", "1.3.6.1.4.1.272.4.16.10.1.25.3000000.0"),
                new OidData("Firmware", "1.3.6.1.4.1.272.4.1.56.0"),
                new OidData("Model", "1.3.6.1.2.1.1.1.0"),
                new OidData("SN", "1.3.6.1.4.1.272.4.1.31.0"),
                new OidData("Config", "1.3.6.1.2.1.1.6.0")
            };
        }

        private void BtnGetSnmpData_Click(object sender, RoutedEventArgs e)
        {
            GetSnmpData(txtHost.Text);
        }

        private void GetSnmpData(string _host)
        {
            //snmpwalk -v3 -l authNoPriv -u [user] -a MD5 - A [password] [host]

            IPAddress hostIP;
            if (!IPAddress.TryParse(_host, out hostIP))
            {
                try
                {
                    hostIP = Dns.GetHostAddresses(_host)[0];
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
            }

            try
            {
                Discovery discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
                ReportMessage report = discovery.GetResponse(5000, new IPEndPoint(hostIP, 161));

                var auth = new MD5AuthenticationProvider(new OctetString(txtPassword.Text));
                var priv = new DefaultPrivacyProvider(auth);

                List<Variable> vList = new List<Variable>();
                foreach (OidData oidData in OidList)
                {
                    vList.Add(new Variable(new ObjectIdentifier(oidData.Oid)));
                }

                GetRequestMessage request = new GetRequestMessage(
                    VersionCode.V3,
                    Messenger.NextMessageId,
                    Messenger.NextRequestId,
                    new OctetString("read"),
                    vList,
                    priv,
                    Messenger.MaxMessageSize,
                    report);

                ISnmpMessage reply = request.GetResponse(5000, new IPEndPoint(hostIP, 161));
                if (reply.Pdu().ErrorStatus.ToInt32() != 0) // != ErrorCode.NoError
                {
                    throw ErrorException.Create(
                        "error in response",
                        hostIP,
                        reply);
                }


                foreach (Variable v in reply.Pdu().Variables)
                {
                    lbOutput.Items.Add(v);
                }

                lbOutput.Items.Add("-------------------------------");
                Listbox_ScrollToBottom();
            }
            catch (SnmpException ex)
            {
                Console.WriteLine(ex);
            }
            catch (SocketException ex)
            {
                Console.WriteLine(ex);
            }
        }

        private void Listbox_ScrollToBottom()
        {
            if (VisualTreeHelper.GetChildrenCount(lbOutput) > 0)
            {
                Border border = (Border)VisualTreeHelper.GetChild(lbOutput, 0);
                ScrollViewer scrollViewer = (ScrollViewer)VisualTreeHelper.GetChild(border, 0);
                scrollViewer.ScrollToBottom();
            }
        }
    }
}
