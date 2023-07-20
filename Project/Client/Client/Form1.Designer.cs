namespace Client
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.textBox_ip = new System.Windows.Forms.TextBox();
            this.textBox_port = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.button_connect = new System.Windows.Forms.Button();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.textBox_username = new System.Windows.Forms.TextBox();
            this.textBox_password = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.comboBox_channel = new System.Windows.Forms.ComboBox();
            this.label6 = new System.Windows.Forms.Label();
            this.button_disconnect = new System.Windows.Forms.Button();
            this.button_enroll = new System.Windows.Forms.Button();
            this.button_authenticate = new System.Windows.Forms.Button();
            this.label3 = new System.Windows.Forms.Label();
            this.textBox_message = new System.Windows.Forms.TextBox();
            this.button_send = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // textBox_ip
            // 
            this.textBox_ip.Location = new System.Drawing.Point(73, 23);
            this.textBox_ip.Name = "textBox_ip";
            this.textBox_ip.Size = new System.Drawing.Size(131, 26);
            this.textBox_ip.TabIndex = 0;
            // 
            // textBox_port
            // 
            this.textBox_port.Location = new System.Drawing.Point(73, 61);
            this.textBox_port.Name = "textBox_port";
            this.textBox_port.Size = new System.Drawing.Size(131, 26);
            this.textBox_port.TabIndex = 1;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(39, 26);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(28, 20);
            this.label1.TabIndex = 3;
            this.label1.Text = "IP:";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(25, 64);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(42, 20);
            this.label2.TabIndex = 4;
            this.label2.Text = "Port:";
            // 
            // button_connect
            // 
            this.button_connect.Location = new System.Drawing.Point(128, 103);
            this.button_connect.Name = "button_connect";
            this.button_connect.Size = new System.Drawing.Size(110, 44);
            this.button_connect.TabIndex = 5;
            this.button_connect.Text = "Connect";
            this.button_connect.UseVisualStyleBackColor = true;
            this.button_connect.Click += new System.EventHandler(this.button_connect_Click);
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(244, 12);
            this.logs.Name = "logs";
            this.logs.Size = new System.Drawing.Size(272, 460);
            this.logs.TabIndex = 8;
            this.logs.Text = "";
            // 
            // textBox_username
            // 
            this.textBox_username.Location = new System.Drawing.Point(107, 173);
            this.textBox_username.Name = "textBox_username";
            this.textBox_username.Size = new System.Drawing.Size(131, 26);
            this.textBox_username.TabIndex = 9;
            // 
            // textBox_password
            // 
            this.textBox_password.Location = new System.Drawing.Point(107, 214);
            this.textBox_password.Name = "textBox_password";
            this.textBox_password.Size = new System.Drawing.Size(131, 26);
            this.textBox_password.TabIndex = 10;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(14, 176);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(87, 20);
            this.label4.TabIndex = 11;
            this.label4.Text = "Username:";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(14, 214);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(82, 20);
            this.label5.TabIndex = 12;
            this.label5.Text = "Password:";
            // 
            // comboBox_channel
            // 
            this.comboBox_channel.BackColor = System.Drawing.SystemColors.Window;
            this.comboBox_channel.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.comboBox_channel.FormattingEnabled = true;
            this.comboBox_channel.Items.AddRange(new object[] {
            "IF100",
            "MATH101",
            "SPS101"});
            this.comboBox_channel.Location = new System.Drawing.Point(107, 256);
            this.comboBox_channel.Name = "comboBox_channel";
            this.comboBox_channel.Size = new System.Drawing.Size(131, 28);
            this.comboBox_channel.TabIndex = 13;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(24, 259);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(72, 20);
            this.label6.TabIndex = 14;
            this.label6.Text = "Channel:";
            // 
            // button_disconnect
            // 
            this.button_disconnect.Enabled = false;
            this.button_disconnect.Location = new System.Drawing.Point(12, 103);
            this.button_disconnect.Name = "button_disconnect";
            this.button_disconnect.Size = new System.Drawing.Size(110, 44);
            this.button_disconnect.TabIndex = 15;
            this.button_disconnect.Text = "Disconnect";
            this.button_disconnect.UseVisualStyleBackColor = true;
            this.button_disconnect.Click += new System.EventHandler(this.button_disconnect_Click);
            // 
            // button_enroll
            // 
            this.button_enroll.Enabled = false;
            this.button_enroll.Location = new System.Drawing.Point(12, 301);
            this.button_enroll.Name = "button_enroll";
            this.button_enroll.Size = new System.Drawing.Size(110, 44);
            this.button_enroll.TabIndex = 16;
            this.button_enroll.Text = "Enroll";
            this.button_enroll.UseVisualStyleBackColor = true;
            this.button_enroll.Click += new System.EventHandler(this.button_enroll_Click);
            // 
            // button_authenticate
            // 
            this.button_authenticate.AutoSize = true;
            this.button_authenticate.Enabled = false;
            this.button_authenticate.Location = new System.Drawing.Point(128, 301);
            this.button_authenticate.Name = "button_authenticate";
            this.button_authenticate.Size = new System.Drawing.Size(110, 44);
            this.button_authenticate.TabIndex = 17;
            this.button_authenticate.Text = "Authenticate";
            this.button_authenticate.UseVisualStyleBackColor = true;
            this.button_authenticate.Click += new System.EventHandler(this.button_authenticate_Click);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(14, 366);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(78, 20);
            this.label3.TabIndex = 18;
            this.label3.Text = "Message:";
            // 
            // textBox_message
            // 
            this.textBox_message.Enabled = false;
            this.textBox_message.Location = new System.Drawing.Point(12, 389);
            this.textBox_message.Name = "textBox_message";
            this.textBox_message.Size = new System.Drawing.Size(226, 26);
            this.textBox_message.TabIndex = 19;
            // 
            // button_send
            // 
            this.button_send.Enabled = false;
            this.button_send.Location = new System.Drawing.Point(73, 421);
            this.button_send.Name = "button_send";
            this.button_send.Size = new System.Drawing.Size(110, 44);
            this.button_send.TabIndex = 20;
            this.button_send.Text = "Send";
            this.button_send.UseVisualStyleBackColor = true;
            this.button_send.Click += new System.EventHandler(this.button_send_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(528, 484);
            this.Controls.Add(this.button_send);
            this.Controls.Add(this.textBox_message);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.button_authenticate);
            this.Controls.Add(this.button_enroll);
            this.Controls.Add(this.button_disconnect);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.comboBox_channel);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.textBox_password);
            this.Controls.Add(this.textBox_username);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.button_connect);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textBox_port);
            this.Controls.Add(this.textBox_ip);
            this.Name = "Form1";
            this.Text = "Client";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.TextBox textBox_ip;
        private System.Windows.Forms.TextBox textBox_port;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button button_connect;
        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.TextBox textBox_username;
        private System.Windows.Forms.TextBox textBox_password;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.ComboBox comboBox_channel;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Button button_disconnect;
        private System.Windows.Forms.Button button_enroll;
        private System.Windows.Forms.Button button_authenticate;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox textBox_message;
        private System.Windows.Forms.Button button_send;
    }
}

