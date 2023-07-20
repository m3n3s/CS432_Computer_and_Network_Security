namespace Server
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
            this.label1 = new System.Windows.Forms.Label();
            this.textBox_port = new System.Windows.Forms.TextBox();
            this.button_listen = new System.Windows.Forms.Button();
            this.logs = new System.Windows.Forms.RichTextBox();
            this.textBox_if100_secret = new System.Windows.Forms.TextBox();
            this.textBox_sps101_secret = new System.Windows.Forms.TextBox();
            this.textBox_math101_secret = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.button_generate_key = new System.Windows.Forms.Button();
            this.if100 = new System.Windows.Forms.RichTextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.math101 = new System.Windows.Forms.RichTextBox();
            this.sps101 = new System.Windows.Forms.RichTextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(42, 20);
            this.label1.TabIndex = 0;
            this.label1.Text = "Port:";
            // 
            // textBox_port
            // 
            this.textBox_port.Location = new System.Drawing.Point(12, 32);
            this.textBox_port.Name = "textBox_port";
            this.textBox_port.Size = new System.Drawing.Size(175, 26);
            this.textBox_port.TabIndex = 1;
            // 
            // button_listen
            // 
            this.button_listen.Location = new System.Drawing.Point(47, 77);
            this.button_listen.Name = "button_listen";
            this.button_listen.Size = new System.Drawing.Size(107, 42);
            this.button_listen.TabIndex = 2;
            this.button_listen.Text = "Listen";
            this.button_listen.UseVisualStyleBackColor = true;
            this.button_listen.Click += new System.EventHandler(this.button_listen_Click);
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(202, 12);
            this.logs.Name = "logs";
            this.logs.Size = new System.Drawing.Size(314, 460);
            this.logs.TabIndex = 3;
            this.logs.Text = "";
            // 
            // textBox_if100_secret
            // 
            this.textBox_if100_secret.Location = new System.Drawing.Point(12, 184);
            this.textBox_if100_secret.Name = "textBox_if100_secret";
            this.textBox_if100_secret.Size = new System.Drawing.Size(175, 26);
            this.textBox_if100_secret.TabIndex = 4;
            // 
            // textBox_sps101_secret
            // 
            this.textBox_sps101_secret.Location = new System.Drawing.Point(12, 311);
            this.textBox_sps101_secret.Name = "textBox_sps101_secret";
            this.textBox_sps101_secret.Size = new System.Drawing.Size(175, 26);
            this.textBox_sps101_secret.TabIndex = 5;
            // 
            // textBox_math101_secret
            // 
            this.textBox_math101_secret.Location = new System.Drawing.Point(12, 249);
            this.textBox_math101_secret.Name = "textBox_math101_secret";
            this.textBox_math101_secret.Size = new System.Drawing.Size(175, 26);
            this.textBox_math101_secret.TabIndex = 6;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(12, 161);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(103, 20);
            this.label2.TabIndex = 7;
            this.label2.Text = "IF100 secret:";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(12, 226);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(133, 20);
            this.label3.TabIndex = 8;
            this.label3.Text = "MATH101 secret:";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(12, 288);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(120, 20);
            this.label4.TabIndex = 9;
            this.label4.Text = "SPS101 secret:";
            // 
            // button_generate_key
            // 
            this.button_generate_key.Location = new System.Drawing.Point(47, 353);
            this.button_generate_key.Name = "button_generate_key";
            this.button_generate_key.Size = new System.Drawing.Size(107, 56);
            this.button_generate_key.TabIndex = 10;
            this.button_generate_key.Text = "Generate Key";
            this.button_generate_key.UseVisualStyleBackColor = true;
            this.button_generate_key.Click += new System.EventHandler(this.button_generate_key_Click);
            // 
            // if100
            // 
            this.if100.Location = new System.Drawing.Point(528, 35);
            this.if100.Name = "if100";
            this.if100.Size = new System.Drawing.Size(314, 125);
            this.if100.TabIndex = 11;
            this.if100.Text = "";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(524, 12);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(55, 20);
            this.label5.TabIndex = 12;
            this.label5.Text = "IF100:";
            // 
            // math101
            // 
            this.math101.Location = new System.Drawing.Point(528, 186);
            this.math101.Name = "math101";
            this.math101.Size = new System.Drawing.Size(314, 125);
            this.math101.TabIndex = 13;
            this.math101.Text = "";
            // 
            // sps101
            // 
            this.sps101.Location = new System.Drawing.Point(528, 337);
            this.sps101.Name = "sps101";
            this.sps101.Size = new System.Drawing.Size(314, 125);
            this.sps101.TabIndex = 14;
            this.sps101.Text = "";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(524, 163);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(85, 20);
            this.label6.TabIndex = 15;
            this.label6.Text = "MATH101:";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(524, 314);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(68, 20);
            this.label7.TabIndex = 16;
            this.label7.Text = "SPS101";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(9F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(854, 484);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.sps101);
            this.Controls.Add(this.math101);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.if100);
            this.Controls.Add(this.button_generate_key);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.textBox_math101_secret);
            this.Controls.Add(this.textBox_sps101_secret);
            this.Controls.Add(this.textBox_if100_secret);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.button_listen);
            this.Controls.Add(this.textBox_port);
            this.Controls.Add(this.label1);
            this.Name = "Form1";
            this.Text = "Server";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox textBox_port;
        private System.Windows.Forms.Button button_listen;
        private System.Windows.Forms.RichTextBox logs;
        private System.Windows.Forms.TextBox textBox_if100_secret;
        private System.Windows.Forms.TextBox textBox_sps101_secret;
        private System.Windows.Forms.TextBox textBox_math101_secret;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Button button_generate_key;
        private System.Windows.Forms.RichTextBox if100;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.RichTextBox math101;
        private System.Windows.Forms.RichTextBox sps101;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label7;
    }
}

