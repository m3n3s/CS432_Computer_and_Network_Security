using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;


namespace Client
{
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool connected = false;
        bool enrolled = false;
        bool authenticated = false;
        Socket clientSocket;

        string ip;
        string portNum;
        string password;
        string username;
        string channel;

        string RSAxmlKey3072EncDec;
        string RSAxmlKey3072SignVer;

        string channelKey = "";
        string channelIV = "";
        string channelHMAC = "";

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();

            // Load keys and plaintexts from Debug/bin folder
            // RSA 3072 keys            
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("server_enc_dec_pub.txt"))
            {
                RSAxmlKey3072EncDec = fileReader.ReadLine();
            }

            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("server_sign_verify_pub.txt"))
            {
                RSAxmlKey3072SignVer = fileReader.ReadLine();
            }

        }

        private void button_connect_Click(object sender, EventArgs e)
        {
            // When the connect button is clicket, it will try to connect to the server through sockets.
            clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Get inputs through GUI
            ip = textBox_ip.Text;
            portNum = textBox_port.Text;
            password = textBox_password.Text;
            username = textBox_username.Text;
            channel = comboBox_channel.Text;
            int port_num;

            // Check if the entered port number is actually a number, if it is continue.
            if (Int32.TryParse(portNum, out port_num) && ip != "")
            {
                try
                {
                    // Connection is formed here.
                    clientSocket.Connect(ip, port_num);
                    
                    button_connect.Enabled = false;
                    button_disconnect.Enabled = true;
                    button_enroll.Enabled = true;
                    button_authenticate.Enabled = true;
                    connected = true;
                    logs.AppendText("Connected to the server. \n");                  

                    // Open a new thread to be able to recieve messages.
                    Thread receiveThread = new Thread(new ThreadStart(Receive));
                    receiveThread.Start();

                }
                catch
                {
                    logs.AppendText("Could not connect to the server. \n");
                    logs.AppendText("Please check IP address and port number again. \n");
                }

            }
            else
            {
                logs.AppendText("Check the port number. \n");
            }
        }

        private void EnrollmentRequest()
        {
            // Connection is succesfull, take the hash of the password
            Byte[] hashedPasswordBytes = hashWithSHA512(password);
            string hashedPassword = generateHexStringFromByteArray(hashedPasswordBytes);

            // Send the required information to server.
            string message = username + "|sep|" + channel + "|sep|" + hashedPassword;
            logs.AppendText("Message to be sent to server: \n" + message + "\n");
            Byte[] encryptedBytes = encryptWithRSA(message, 3072, RSAxmlKey3072EncDec);
            //logs.AppendText("In encrypted form: \n" + Encoding.Default.GetString(encryptedBytes) + " \n");
            message = "Enrollment|sep|" + Encoding.Default.GetString(encryptedBytes);
            Byte[] sending = Encoding.Default.GetBytes(message);
            clientSocket.Send(sending);
        }

        private void AuthenticationRequest()
        {
            logs.AppendText("\nIn authentication process... \n");
            string message = "AuthenticationRequest|sep|" + username;
            logs.AppendText("Message to be sent to server: \n" + message + "\n");
            Byte[] authReq = new Byte[128];
            authReq = Encoding.Default.GetBytes(message);

            // Send the required info for the challenge-response protocol to start.
            clientSocket.Send(authReq);
            logs.AppendText("Challenge-response protocol initiated. \n");
        }

        private void Receive()
        {
            // While connected to the server, listen for coming messages.
            while (connected)
            {
                try
                {
                    Byte[] buffer = new Byte[1024];
                    clientSocket.Receive(buffer);

                    string message = Encoding.Default.GetString(buffer);
                    message = message.Trim('\0');

                    // Enrollment response from server.
                    if (message.Contains("Enrollment"))
                    {
                        // Get the signature of the response
                        string signed = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[2];
                        // Get the response
                        string response = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[1];

                        //logs.AppendText("Recieved signed response from server is: \n" + signed + "\n");
                        logs.AppendText("Recieved signed response from server. \n");

                        bool verified = verifyWithRSA(response, 3072, RSAxmlKey3072SignVer, Encoding.Default.GetBytes(signed));

                        // If response is verified and there is success written, client is enrolled.
                        if (verified && response.Contains("Success"))
                        {
                            if (response.Contains("Already enrolled"))
                                logs.AppendText("Already enrolled, proceed with authentication. \n");
                            else
                                logs.AppendText("Successfully enrolled. \n");

                            enrolled = true;
                        }

                        // If the respons consists of error, it means client could not enroll.
                        else if (verified && response.Contains("Error"))
                        {
                            logs.AppendText("Could not enroll, username is already taken. \n");
                            logs.AppendText("Please try again with a different username. \n");
                        }

                        // The case where server is not verified.
                        else if (!verified)
                        {
                            logs.AppendText("Response from server is not verified. \n");
                        }
                    }

                    // Server's response to authentication request of the client
                    // which is a 128 bit random number.
                    else if (message.Contains("Challenge"))
                    {
                        // Get the randomized challenge.
                        string challenge = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[1];
                        logs.AppendText("Challenge sent from server: \n" + challenge + "\n");
                        Byte[] hashedPasswordBytes = hashWithSHA512(password);
                        string hashedPassword = generateHexStringFromByteArray(hashedPasswordBytes);
                        Byte[] key = new Byte[16]; // 128 bits = 16 bytes
                        Array.Copy(Encoding.Default.GetBytes(hashedPassword), 0, key, 0, 16);
                        Byte[] challengeHMACBytes = applyHMACwithSHA512(challenge, key);
                        logs.AppendText("HMAC on challenge: " + Encoding.Default.GetString(challengeHMACBytes) + " \n");

                        clientSocket.Send(challengeHMACBytes);

                        clientSocket.Receive(buffer); // Get the response first
                        string encryptedString = Encoding.Default.GetString(buffer);
                        encryptedString = encryptedString.Trim('\0');

                        clientSocket.Receive(buffer); // Get the signature
                        string signed = Encoding.Default.GetString(buffer);
                        signed = signed.Trim('\0');
                        logs.AppendText("\nRecieved signed and encrypted response from server. \n");

                        // Verify the encrypted string sent from server.
                        bool verified = verifyWithRSA(encryptedString, 3072, RSAxmlKey3072SignVer, Encoding.Default.GetBytes(signed));

                        if (encryptedString.Contains("unavailable"))
                        {
                            logs.AppendText("Channel is unavailable. \n");
                            continue;
                        }

                        if (verified)
                        {
                            // Get the secure channel key and iv
                            string response = encryptedString.Split(new[] { "|sep|" }, StringSplitOptions.None)[0];
                            string encryptedKey = encryptedString.Split(new[] { "|sep|" }, StringSplitOptions.None)[1];
                            string encryptedIV = encryptedString.Split(new[] { "|sep|" }, StringSplitOptions.None)[2];
                            string encryptedHMAC = encryptedString.Split(new[] { "|sep|" }, StringSplitOptions.None)[3];


                            // If verified, then client is authenticated.
                            Byte[] aesKey = new Byte[16];
                            Byte[] aesIV = new Byte[16];
                            Array.Copy(Encoding.Default.GetBytes(hashedPassword), 32, aesKey, 0, 16);
                            Array.Copy(Encoding.Default.GetBytes(hashedPassword), 48, aesIV, 0, 16);

                            Byte[] decryptedByte = decryptWithAES128(encryptedKey, aesKey, aesIV);
                            channelKey = generateHexStringFromByteArray(decryptedByte);

                            decryptedByte = decryptWithAES128(encryptedIV, aesKey, aesIV);
                            channelIV = generateHexStringFromByteArray(decryptedByte);

                            decryptedByte = decryptWithAES128(encryptedHMAC, aesKey, aesIV);
                            channelHMAC = generateHexStringFromByteArray(decryptedByte);

                            logs.AppendText("Response from server: \n" + response + "\n\n\n");
                            logs.AppendText("Channel key: " + channelKey + "\n");
                            logs.AppendText("Channel IV: " + channelIV + "\n");
                            logs.AppendText("Channel HMAC: " + channelHMAC + "\n");

                            authenticated = true;

                            button_send.Enabled = true;
                            textBox_message.Enabled = true;
                            button_enroll.Enabled = false;
                            button_authenticate.Enabled = false;
                            textBox_username.Enabled = false;
                            textBox_password.Enabled = false;
                            comboBox_channel.Enabled = false;
                        }

                        else
                        {
                            logs.AppendText("Authentication unsuccesfull. \n");
                        }

                    }

                    else if (message.Contains("Message"))
                    {
                        string encrypted = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[1];
                        string hmac = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[2];

                        Byte[] decrypt = decryptWithAES128(encrypted, hexStringToByteArray(channelKey), hexStringToByteArray(channelIV));
                        string decryptStr = Encoding.Default.GetString(decrypt);

                        Byte[] c = applyHMACwithSHA512(encrypted, hexStringToByteArray(channelHMAC));
                        string cStr = Encoding.Default.GetString(c);

                        if (hmac == cStr)
                        {
                            logs.AppendText("\nMessage from channel: \n");
                            logs.AppendText(decryptStr + "\n");
                        }
                        else
                        {
                            logs.AppendText("Something went wrong. \n");
                        }
                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("Connection has lost with the server. \n");
                    }

                    clientSocket.Close();
                    connected = false;
                    enrolled = false;
                    button_connect.Enabled = true;
                    button_disconnect.Enabled = false;
                    button_enroll.Enabled = false;
                    button_authenticate.Enabled = false;
                    button_send.Enabled = false;
                }
            }
        }

        private void button_disconnect_Click(object sender, EventArgs e)
        {
            // Function to handle the disconnect button.

            clientSocket.Close();
            connected = false;
            enrolled = false;
            button_connect.Enabled = true;
            button_disconnect.Enabled = false;
            button_enroll.Enabled = false;
            button_authenticate.Enabled = false;
            button_send.Enabled = false;
            textBox_message.Enabled = false;
            textBox_username.Enabled = true;
            textBox_password.Enabled = true;
            comboBox_channel.Enabled = true;
        }

        private void button_enroll_Click(object sender, EventArgs e)
        {
            password = textBox_password.Text;
            username = textBox_username.Text;
            channel = comboBox_channel.Text;

            // Check if any field on the GUI is empty, if so wait for it to be filled.
            if (password == "" || username == "" || channel == "")
                logs.AppendText("Please don't leave any field empty. \n");
            else
                EnrollmentRequest();
        }

        private void button_authenticate_Click(object sender, EventArgs e)
        {
            password = textBox_password.Text;
            username = textBox_username.Text;
            channel = comboBox_channel.Text;

            // Check if any field on the GUI is empty, if so wait for it to be filled.
            if (password == "" || username == "")
                logs.AppendText("Please don't leave username or password empty. \n");
            else
                AuthenticationRequest();
        }

        private void button_send_Click(object sender, EventArgs e)
        {
            // Send encrypted message to server with hmac
            string message = textBox_message.Text;

            if (message != "")
            {
                Byte[] encrypted = encryptWithAES128(message, hexStringToByteArray(channelKey), hexStringToByteArray(channelIV));
                Byte[] hmac = applyHMACwithSHA512(Encoding.Default.GetString(encrypted), hexStringToByteArray(channelHMAC));

                string m = "Message|sep|" + Encoding.Default.GetString(encrypted) + "|sep|" + Encoding.Default.GetString(hmac);

                clientSocket.Send(Encoding.Default.GetBytes(m));

                textBox_message.Text = String.Empty;
            }           
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Function for closing the GUI.

            connected = false;
            terminating = true;
            Environment.Exit(0);
        }

        // Helper functions from labs.
        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        public static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // encryption with AES-128
        static byte[] encryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CBC;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;

            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        // hash function: SHA-512
        static byte[] hashWithSHA512(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA512CryptoServiceProvider sha512Hasher = new SHA512CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha512Hasher.ComputeHash(byteInput);

            return result;
        }

        // RSA encryption with varying bit length
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // RSA decryption with varying bit length
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // verifying with RSA
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA256", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        // HMAC with SHA-512
        static byte[] applyHMACwithSHA512(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA512 hmacSHA512 = new HMACSHA512(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA512.ComputeHash(byteInput);

            return result;
        }

        // Decryption with AES-128
        static byte[] decryptWithAES128(string input, byte[] key, byte[] IV)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);

            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CBC;
            // feedback size should be equal to block size
            // aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        
    }
}
