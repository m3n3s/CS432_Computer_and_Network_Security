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
using System.IO;


namespace Server
{
    public partial class Form1 : Form
    {
        struct User
        {
            // Struct for holding the information of each client.
            public string username;
            public string password;
            public string channel;
            public Socket socket;

            public User(string username, string password, string channel, Socket socket = null)
            {
                this.username = username;
                this.password = password;
                this.channel = channel;
                this.socket = socket;
            }
        }

        bool terminating = false;
        bool listening = false;
        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        List<Socket> socketList = new List<Socket>(); // list of client sockets that are connected to server
        List<User> users = new List<User>(); // List of users that have been enrolled and be remembered.
        List<User> online = new List<User>(); // List of users who are authenticated to a channel.

        string RSAxmlKey3072EncDec;
        string RSAxmlKey3072SignVer;
        string db = "db.txt";

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();

            // Load keys and plaintexts from Debug/bin folder
            // RSA 3072 keys            
            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("server_enc_dec_pub_prv.txt"))
            {
                RSAxmlKey3072EncDec = fileReader.ReadLine();
            }

            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader("server_sign_verify_pub_prv.txt"))
            {
                RSAxmlKey3072SignVer = fileReader.ReadLine();
            }

            // Load enrolled users
            if (!File.Exists(db)){
                File.Create(db);
            }

            using (System.IO.StreamReader fileReader =
            new System.IO.StreamReader(db))
            {
                string line;

                while((line = fileReader.ReadLine()) != null)
                {
                    User user = new User();

                    user.username = line.Split(',')[0];
                    user.password = line.Split(',')[1];
                    user.channel = line.Split(',')[2];

                    users.Add(user);
                }
            }
        }

        private void button_listen_Click(object sender, EventArgs e)
        {
            // Clicking of the listen button, server starts to listen on the port that is inputted from the GUI.
            string portnum = textBox_port.Text;
            int port_num;

            // Check if port number is valid, if so , continue.
            if (Int32.TryParse(portnum, out port_num))
            {
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, port_num));
                serverSocket.Listen(3);

                listening = true;
                button_listen.Enabled = false;

                // Start a new thred to accept the incoming connections through the port.
                Thread acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();

                logs.AppendText("Started listening. \n");
            }
            else
            {
                logs.AppendText("Check the port number. \n");
            }
        }

        private void Accept()
        {
            // Accept function, accepts the incoming socket connections while the server is running.
            // It will stop when server is closed.

            while (listening)
            {
                try
                { 
                    // New client is accepted and added to the clients' socket list.
                    Socket newClient = serverSocket.Accept();
                    socketList.Add(newClient);
                    logs.AppendText("A client is connected. \n");

                    // Start a new thread for each of the clients that will recive the messages coming from them.
                    Thread receiveThread = new Thread(new ThreadStart(Receive));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                    {
                        listening = false;
                    }
                    else
                    {
                        logs.AppendText("Socket has stopped working. \n");
                    }
                }
            }
        }
        

        private void Receive()
        {
            // Recive from the clients' respective sockets, and keep the user information they sent.
            // Will continue to listen until server is not stopped and there is a connection.

            Socket s = socketList[socketList.Count - 1]; //client that is newly added
            bool connected = true;
            User user = new User();

            while (!terminating && connected)
            {
                try
                {
                    Byte[] buffer = new Byte[1024];
                    s.Receive(buffer);

                    string message = Encoding.Default.GetString(buffer);
                    message = message.Trim('\0');

                    if (message.Contains("Enrollment"))
                    {
                        // Client is in enrollment stage, perform the necessary tasks here.

                        string encryptedString = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[1]; // Get the encrypted part.
                        Byte [] decryptedBytes = decryptWithRSA(encryptedString, 3072, RSAxmlKey3072EncDec);
                        string decrypted = Encoding.Default.GetString(decryptedBytes);
                        logs.AppendText("Enrollment request: \n" + decrypted + "\n");

                        string[] args = decrypted.Split(new[] { "|sep|" }, StringSplitOptions.None);
                        string username = args[0], channel = args[1], password = args[2];
                        logs.AppendText("Username is: " + username + "\n");
                        logs.AppendText("Subscribed channel is: " + channel + "\n");
                        logs.AppendText("Hashed password is: " + password + "\n");

                        user = new User(username, password, channel);
                        string enteredUsername = user.username;
                        string enteredPassword = user.password;

                        bool contains = users.Any(u => u.username == enteredUsername);
                        string rememberedPassword = users.Find(u => u.username == enteredUsername).password;

                        // Remember if user was enrolled before, if it is, continue with authentication.
                        if (contains && rememberedPassword == enteredPassword)
                        {
                            string response = "Success, Already enrolled.";
                            logs.AppendText("Response to the client is: \n" + response + "\n");

                            string signedResponse = Encoding.Default.GetString(signWithRSA(response, 3072, RSAxmlKey3072SignVer));
                            //logs.AppendText("Signed response is: \n " + signedResponse + "\n");
                            logs.AppendText("Signed response is sent.");

                            Byte[] sending = Encoding.Default.GetBytes("Enrollment|sep|" + response + "|sep|" + signedResponse);
                            s.Send(sending);
                        }

                        // Check if the entered username was already used to enroll. 
                        else if (contains)
                        {
                            // Send back a message saying username is already enrolled.
                            string response = "Error, Enrollment not succesfull, username has already been taken.";

                            string signedResponse = Encoding.Default.GetString(signWithRSA(response, 3072, RSAxmlKey3072SignVer));
                            logs.AppendText("Signed response is: \n " + signedResponse + "\n");
                            logs.AppendText("Response to the client is: \n" + response + "\n\n\n");

                            Byte[] sending = Encoding.Default.GetBytes("Enrollment|sep|" + response + "|sep|" + signedResponse);
                            s.Send(sending);
                        }

                        // Else, the user is a new user and the enrollment processes will happen.
                        else
                        {
                            // Add the user to enrolled users list.
                            users.Add(user);
                            logs.AppendText("New user added. \n");

                            // Save the new user to local db
                            using (StreamWriter sw = File.AppendText(db))
                            {
                                string line = user.username + "," + user.password + "," + user.channel;

                                sw.WriteLine(line);
                            }

                            // Send back a message saying enrollment is succesfull.
                            string response = "Success, Enrollment is succesful.";
                            logs.AppendText("Response to the client is: \n" + response + "\n");

                            string signedResponse = Encoding.Default.GetString(signWithRSA(response, 3072, RSAxmlKey3072SignVer));
                            //logs.AppendText("Signed response is: \n " + signedResponse + "\n");
                            logs.AppendText("Signed response is sent.");

                            Byte[] sending = Encoding.Default.GetBytes("Enrollment|sep|" + response + "|sep|" + signedResponse);
                            s.Send(sending);
                        }
                    }

                    else if (message.Contains("AuthenticationRequest"))
                    {
                        // Client is in authentication stage. Necessary tasks are performed here.
                        string clientUsername = message.Split(new[] { "|sep|" }, StringSplitOptions.None)[1];

                        //TODO: Check if user is enrolled
                        user = users.Find(u => u.username == clientUsername);
                        
                        if (user.username == null)
                        {
                            logs.AppendText("No user with the username: " + clientUsername + " exists in database! \n");
                            continue;
                        }

                        // Add the current connected socket to the corresponding user information.
                        int idx = users.FindIndex(u => u.username == clientUsername);
                        user.socket = s;
                        users[idx] = user;

                        
                        // Random 128-bit number to be used as challenge.
                        Byte[] random16byte = GenerateRandomData(16); // 128 bit = 16 byte

                        // Send the challenge to client
                        string challenge = Encoding.Default.GetString(random16byte);
                        logs.AppendText("Randomly generated challenge: \n" + challenge + "\n");                   
                        string challengeMessage = "Challenge|sep|" + challenge;
                        Byte[] challengeMessageBytes = Encoding.Default.GetBytes(challengeMessage);
                        s.Send(challengeMessageBytes);

                        // Client sends HMAC version of the challenge
                        Byte[] buffer2 = new Byte[1024];
                        s.Receive(buffer2);
                        message = Encoding.Default.GetString(buffer2);
                        message = message.Trim('\0');
                        logs.AppendText("HMAC on challenge recieved from client " + user.username + " : \n" + message + "\n");

                        Byte[] key = new Byte[16]; // 16 bytes = 128 bits
                        Byte[] hashedPasswordBytes = Encoding.Default.GetBytes(user.password); // Password is already hashed
                        Array.Copy(hashedPasswordBytes, 0, key, 0, 16);

                        logs.AppendText("Key for checking HMAC: " + Encoding.Default.GetString(key) + "\n");

                        Byte [] hmac = applyHMACwithSHA512(challenge, key);
                        string hmacString = Encoding.Default.GetString(hmac);
                        logs.AppendText("HMAC calculated to check with the client's: " + hmacString + "\n");

                        Byte[] AESkey = new Byte[16];
                        Byte[] AESiv = new Byte[16];
                        Array.Copy(hashedPasswordBytes, 32, AESkey, 0, 16);
                        Array.Copy(hashedPasswordBytes, 48, AESiv, 0, 16);
                        logs.AppendText("Key for AES: " + Encoding.Default.GetString(AESkey) + "\n");
                        logs.AppendText("IV for AES: " + Encoding.Default.GetString(AESiv) + "\n");

                        // If HMAC values don't match, not authenticated.

                        if (hmacString != message)
                        {
                            // Client's hmac was not verified
                            string response = "Authentication Unsuccessful.";
                            logs.AppendText("Authentication Unsuccessful; HMACs are not the same. \n");                        

                            Byte [] encrypted = encryptWithAES128(response, AESkey, AESiv);
                            string encryptedString = Encoding.Default.GetString(encrypted);
                            Byte[] signed = signWithRSA(encryptedString, 3072, RSAxmlKey3072SignVer);

                            s.Send(Encoding.Default.GetBytes(response));
                            s.Send(signed);
                            logs.AppendText("Authentication response encrypted with AES128: \n" + encryptedString + "\n");
                        }
                        // Authentication is succesfull, but server has not generated keys
                        else if (!keysGenerated)
                        {
                            // Channel is unavailable.
                            string response = "Channel is unavailable.";
                            logs.AppendText("Channel is unavailable. \n");

                            Byte[] encrypted = encryptWithAES128(response, AESkey, AESiv);
                            string encryptedString = Encoding.Default.GetString(encrypted);
                            Byte[] signed = signWithRSA(encryptedString, 3072, RSAxmlKey3072SignVer);

                            s.Send(Encoding.Default.GetBytes(response));
                            s.Send(signed);
                            logs.AppendText("Authentication response encrypted with AES128: \n" + encryptedString + "\n");
                        }

                        // HMACs match and client is authenticated.
                        else
                        {
                            online.Add(user);

                            // Client's hmac was verified

                            // ---- Encrypt channel key and iv
                            string channelKey = "";
                            string channelIV = "";
                            string channelHMAC = "";

                            switch (user.channel)
                            {
                                case "IF100":
                                    channelKey = Encoding.Default.GetString(if100AES);
                                    channelIV = Encoding.Default.GetString(if100IV);
                                    channelHMAC = Encoding.Default.GetString(if100HMAC);
                                    break;
                                case "MATH101":
                                    channelKey = Encoding.Default.GetString(math101AES);
                                    channelIV = Encoding.Default.GetString(math101IV);
                                    channelHMAC = Encoding.Default.GetString(math101HMAC);
                                    break;
                                case "SPS101":
                                    channelKey = Encoding.Default.GetString(sps101AES);
                                    channelIV = Encoding.Default.GetString(sps101IV);
                                    channelHMAC = Encoding.Default.GetString(sps101HMAC);
                                    break;
                            }

                            Byte [] encryptedKey = encryptWithAES128(channelKey, AESkey, AESiv);
                            Byte [] encryptedIV = encryptWithAES128(channelIV, AESkey, AESiv);
                            Byte[] encryptedHMAC = encryptWithAES128(channelHMAC, AESkey, AESiv);

                            string response = "Authentication Successful.|sep|" + Encoding.Default.GetString(encryptedKey) + "|sep|" + Encoding.Default.GetString(encryptedIV) + "|sep|" + Encoding.Default.GetString(encryptedHMAC);
                            Byte[] signed = signWithRSA(response, 3072, RSAxmlKey3072SignVer);

                            s.Send(Encoding.Default.GetBytes(response));
                            Thread.Sleep(1000);
                            s.Send(signed);

                            logs.AppendText("Authentication response encrypted with AES128: \n" + response + "\n");
                            logs.AppendText("\nAuthentication Successful. Welcome, " + user.username + "\n\n\n");
                        }

                    }

                    else if (message.Contains("Message"))
                    {
                        switch (user.channel)
                        {
                            case "IF100":
                                if100.AppendText("Message to be relayed: " + message + "\n");
                                break;
                            case "MATH101":
                                math101.AppendText("Message to be relayed: " + message + "\n");
                                break;
                            case "SPS101":
                                sps101.AppendText("Message to be relayed: " + message + "\n");
                                break;
                        }

                        // Client is sending a message to the subscribed channel
                        for (int i = 0; i < online.Count; i++)
                        {
                            User u = online[i];
                            if (u.channel == user.channel)
                            {
                                try
                                {
                                    if (u.socket != null && u.socket.Connected)
                                        u.socket.Send(Encoding.Default.GetBytes(message));
                                }
                                catch
                                {
                                    logs.AppendText("Something went wrong while relaying a message. \n");
                                }
                            }
                        }
                    }


                }
                catch
                {
                    if (!terminating)
                    {
                        logs.AppendText("Client disconnected. \n");
                        online.Remove(user);
                    }

                    s.Close();
                    socketList.Remove(s);
                    user.socket = null;
                    connected = false;
                }
            }

        }

        // Variables for master secrets:
        Byte[] if100Hashed;
        Byte[] if100AES;
        Byte[] if100IV;
        Byte[] if100HMAC;
        Byte[] math101Hashed;
        Byte[] math101AES;
        Byte[] math101IV;
        Byte[] math101HMAC;
        Byte[] sps101Hashed;
        Byte[] sps101AES;
        Byte[] sps101IV;
        Byte[] sps101HMAC;
        bool keysGenerated = false;

        private void button_generate_key_Click(object sender, EventArgs e)
        {
            string if100Secret = textBox_if100_secret.Text;
            string math101Secret = textBox_math101_secret.Text;
            string sps101Secret = textBox_sps101_secret.Text;

            if (if100Secret == "" || math101Secret == "" || sps101Secret == "")
                logs.AppendText("Please enter all master secrets. \n");

            else
            {
                // Hash the master secrets
                if100Hashed = hashWithSHA512(if100Secret);
                if100AES = new Byte[16];
                if100IV = new Byte[16];
                if100HMAC = new Byte[16];
                Array.Copy(if100Hashed, 0, if100AES, 0, 16);
                Array.Copy(if100Hashed, 16, if100IV, 0, 16);
                Array.Copy(if100Hashed, 32, if100HMAC, 0, 16);

                math101Hashed = hashWithSHA512(math101Secret);
                math101AES = new Byte[16];
                math101IV = new Byte[16];
                math101HMAC = new Byte[16];
                Array.Copy(math101Hashed, 0, math101AES, 0, 16);
                Array.Copy(math101Hashed, 16, math101IV, 0, 16);
                Array.Copy(math101Hashed, 32, math101HMAC, 0, 16);

                sps101Hashed = hashWithSHA512(sps101Secret);
                sps101AES = new Byte[16];
                sps101IV = new Byte[16];
                sps101HMAC = new Byte[16];
                Array.Copy(sps101Hashed, 0, sps101AES, 0, 16);
                Array.Copy(sps101Hashed, 16, sps101IV, 0, 16);
                Array.Copy(sps101Hashed, 32, sps101HMAC, 0, 16);

                keysGenerated = true;
                button_generate_key.Enabled = false;
                textBox_if100_secret.Enabled = false;
                textBox_math101_secret.Enabled = false;
                textBox_sps101_secret.Enabled = false;
                logs.AppendText("Keys generated.");

                logs.AppendText("\nIF100 AES Key: \n" + generateHexStringFromByteArray(if100AES));
                logs.AppendText("\nIF100 IV: \n" + generateHexStringFromByteArray(if100IV));
                logs.AppendText("\nIF100 HMAC Key: \n" + generateHexStringFromByteArray(if100HMAC));

                logs.AppendText("\n\nMATH101 AES Key: \n" + generateHexStringFromByteArray(math101AES));
                logs.AppendText("\nMATH101 IV: \n" + generateHexStringFromByteArray(math101IV));
                logs.AppendText("\nMATH101 HMAC Key: \n" + generateHexStringFromByteArray(math101HMAC));

                logs.AppendText("\n\nSPS101 AES Key: \n" + generateHexStringFromByteArray(sps101AES));
                logs.AppendText("\nSPS101 IV: \n" + generateHexStringFromByteArray(sps101IV));
                logs.AppendText("\nSPS101 HMAC Key: \n" + generateHexStringFromByteArray(sps101HMAC));
                logs.AppendText("\n\n");
            }
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // Function for ending processes when server is closed.
            listening = false;
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

        // signing with RSA
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA256");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        static byte[] GenerateRandomData(int len)
        {
            var rndx = new byte[len];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(rndx);
            }
            return rndx;
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

    }
}
