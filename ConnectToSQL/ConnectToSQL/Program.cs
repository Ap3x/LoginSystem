/*
 * In the App.config file you can change Key1 value to fit AES Key of preference
 */
using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Text;
using System.Security.Cryptography;
using System.Configuration;
using System.Collections.Specialized;
using System.IO;
using static System.Console;
using System.Data;

namespace ConnectToSQL
{
    class Program   
    {
        #region
        private static string preHash;
        private static string databaseCheckUser;
        private static string databaseCheckPass;
        private static string user;
        private static string saltf;
        private static string saltb;
        private static string comb;
        private static string passwordHash;
        private static int choice;
        private static int choiceEncrypt;
        static string sAttr = ConfigurationManager.AppSettings.Get("Key0");
        static string sAttr2 = ConfigurationManager.AppSettings.Get("Key1");
        #endregion
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            WriteLine("Welcome to Noah's Database\n" +
                      "(Hosted local only)\n");
            TOP:
            Console.ForegroundColor = ConsoleColor.Gray;
            Write("Which encryption method and table would you like to use?" + Environment.NewLine +
                  "1) MD5 hash with Salt (Table_1)" + Environment.NewLine +
                  "2) AES 256 (Table_2)" + Environment.NewLine +
                  "3) SHA 512 (Table_3)" + Environment.NewLine);
            Write("Choice:");
            try
            {
                choiceEncrypt = Convert.ToInt32(ReadLine());
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLine("Please enter either 1,2, or 3 only");
                Console.ForegroundColor = ConsoleColor.Gray;
                goto TOP;
            }
            if (choiceEncrypt != 1 && choiceEncrypt != 2 && choiceEncrypt != 3)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLine("Please enter either 1, 2, or 3 only");
                goto TOP;
            }
            RETRYNEW:
            WriteLine("\nWhat would you like to do?\n" +
                      "1) Add a User to Database\n" +
                      "2) Check if User is in Database\n" +
                      "3) EXIT");
            Write("Choice: ");
            try{
                choice = Convert.ToInt32(ReadLine());
            }
            catch{
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLine("Please enter either 1,2, or 3 only");
                Console.ForegroundColor = ConsoleColor.Gray;
                goto RETRYNEW;
            }
            if (choice != 1 && choice != 2 && choice != 3){
                Console.ForegroundColor = ConsoleColor.Red;
                WriteLine("Please enter either 1, 2, or 3 only");
                goto RETRYNEW;
            }

            using (SqlConnection noah = new SqlConnection($"{sAttr}"))
            {
                //Commands to retrieve and add to database
                #region
                //Uncomment the two lines below for MD5
                SqlCommand cmd1 = new SqlCommand("SELECT * FROM [dbo].[Table_1]", noah);
                SqlCommand addHash1 = new SqlCommand($"INSERT INTO Table_1 (hash,userName) VALUES(@hash,@userName)", noah);

                //Uncomment the two lines below for AES256
                SqlCommand cmd2 = new SqlCommand("SELECT * FROM [dbo].[Table_2]", noah);
                SqlCommand addHash2 = new SqlCommand($"INSERT INTO Table_2 (hash,userName) VALUES(@hash,@userName)", noah);

                //Uncomment the two lines below for SHA512
                SqlCommand cmd3 = new SqlCommand("SELECT * FROM [dbo].[Table_3]", noah);
                SqlCommand addHash3 = new SqlCommand($"INSERT INTO Table_3 (hash,userName) VALUES(@hash,@userName)", noah);
                #endregion

                while(choice != 3)
                {
                    if (choice == 1) {
                        WriteLine("\nAdd a User to the Database");
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Write("Username:");
                        user = ReadLine();
                        Write("Password:");
                        while (true)
                        {
                            var key = System.Console.ReadKey(true);
                            if (key.Key == ConsoleKey.Enter)
                                break;
                            preHash += key.KeyChar;
                        }
                        Console.ForegroundColor = ConsoleColor.Gray;
                        if (choiceEncrypt == 1)
                        {
                            using (MD5 md5Hash = MD5.Create())
                            {
                                passwordHash = GetMd5Hash(md5Hash, preHash);        
                                saltf = GetMd5Hash(md5Hash, RandomString(64));
                                saltb = GetMd5Hash(md5Hash, RandomString(64));
                                comb = (String.Concat(saltf, passwordHash, saltb));
                            }
                            addHash1.Parameters.Add("@hash", SqlDbType.VarChar, 96).Value = comb;
                            addHash1.Parameters.Add("@userName", SqlDbType.VarChar, 20).Value = user;
                            noah.Open();
                            addHash1.ExecuteNonQuery();
                            goto RETRYNEW;
                        }
                        if (choiceEncrypt == 2)
                        {
                            string cryptedString = EncryptText(preHash, sAttr2);
                            addHash2.Parameters.Add("@hash", SqlDbType.VarChar, 8000).Value = cryptedString;
                            addHash2.Parameters.Add("@userName", SqlDbType.VarChar, 20).Value = user;
                            noah.Open();
                            addHash2.ExecuteNonQuery();
                            goto RETRYNEW;
                        }
                        if (choiceEncrypt == 3)
                        {
                            passwordHash = GenerateSHA512String(preHash);
                            saltf = GenerateSHA512String(RandomString(64));
                            saltb = GenerateSHA512String(RandomString(64));
                            comb = (String.Concat(saltf, passwordHash, saltb));
     
                            addHash3.Parameters.Add("@hash", SqlDbType.VarChar, 10000).Value = comb;
                            addHash3.Parameters.Add("@userName", SqlDbType.VarChar, 20).Value = user;
                            noah.Open();
                            addHash3.ExecuteNonQuery();
                            goto RETRYNEW;
                        }
                    }
                    if (choice == 2)
                    {
                        if (choiceEncrypt == 1)
                            {
                                // This region checks if its in the database and
                                int attempts = 0;
                                LOGIN:
                                attempts++;
                                noah.Open();
                                SqlDataReader reader = cmd1.ExecuteReader();
                                if (attempts != 4)
                                {

                                WriteLine(Environment.NewLine + "Check if it's in the database");
                                Console.ForegroundColor = ConsoleColor.Cyan;
                                Write("Username:");
                                    databaseCheckUser = ReadLine();
                                    Write("Password:");
                                while (true)
                                {
                                    var key = System.Console.ReadKey(true);
                                    if (key.Key == ConsoleKey.Enter)
                                        break;
                                    databaseCheckPass += key.KeyChar;
                                }
                                Console.ForegroundColor = ConsoleColor.Gray;
                                using (MD5 md5Hash = MD5.Create())
                                    {
                                        databaseCheckPass = GetMd5Hash(md5Hash, databaseCheckPass);
                                    }
                                RETRY:
                                bool found = false;
                                    while (reader.Read())
                                    {
                                        string compare = reader.GetString(0);
                                        compare = compare.Substring(32, 32);
                                        string usernameCOMPARE = reader.GetString(1);
                                        
                                        if ((compare.Length == databaseCheckPass.Length) && (databaseCheckUser == usernameCOMPARE))
                                        {
                                            int i = 0;
                                            while ((i < compare.Length) && (compare[i] == databaseCheckPass[i]))
                                            {
                                                i += 1;
                                            }
                                            if (i == compare.Length)
                                            {
                                                found = true;
                                            }
                                        }
                                        if (found)
                                        {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("\nAccess Granted");
                                        Console.ForegroundColor = ConsoleColor.Gray;
                                        goto RETRYNEW;

                                        }
                                        else
                                        {
                                      
                                        goto RETRY;
                                        }
                                    
                                }
                                reader.Close();
                                noah.Close();
                                if (found)
                                {
                                    goto RETRYNEW;
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("\nAccess Denied");
                                    Console.ForegroundColor = ConsoleColor.Gray;
                                    goto LOGIN;

                                }
                            }

                                else
                                {
                                Console.ForegroundColor = ConsoleColor.Red;
                                noah.Close();
                                WriteLine("\nSorry you've exhausted your numbear of attempts\n Closing console GOOD BYE!!!");
                                break;
                                }
                            }
                        if (choiceEncrypt == 2)
                        {
                            int attempts2 = 0;
                            LOGIN2:
                            attempts2++;
                            noah.Open();
                            SqlDataReader reader2 = cmd2.ExecuteReader();
                            if (attempts2 != 4)
                            {
                                Write(Environment.NewLine + "Check if it's in the database" + Environment.NewLine + "Username:");
                                databaseCheckUser = ReadLine();
                                Write("Password:");
                                while (true)
                                {
                                    var key = System.Console.ReadKey(true);
                                    if (key.Key == ConsoleKey.Enter)
                                        break;
                                    databaseCheckPass += key.KeyChar;
                                }

                                RETRY:
                                bool found = false;
                                while (reader2.Read())
                                {
                                    string compare = reader2.GetString(0);
                                    compare = DecryptText(compare, sAttr2);
                                    string usernameCOMPARE = reader2.GetString(1);

                                    if ((databaseCheckUser == usernameCOMPARE) && (compare == databaseCheckPass))
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("Access Granted");
                                        found = true;
                                        Console.ForegroundColor = ConsoleColor.Gray;
                                        goto RETRYNEW;
                                    }
                                    else
                                    {
                                       goto RETRY;
                                    }

                                }

                                reader2.Close();
                                noah.Close();
                                if (found)
                                {
                                    goto RETRYNEW;
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("\nAccess Denied");
                                    Console.ForegroundColor = ConsoleColor.Gray;
                                    goto LOGIN2;

                                }

                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                noah.Close();
                                WriteLine("\nSorry you've exhausted your numbear of attempts\n Closing console GOOD BYE!!!");
                                break;
                            }
                        }
                        if (choiceEncrypt == 3)
                        {
                            // This region checks if its in the database and
                            int attempts3 = 0;
                            LOGIN3:
                            attempts3++;
                            noah.Open();
                            SqlDataReader reader3 = cmd3.ExecuteReader();
                            if (attempts3 != 4)
                            {
                                Write(Environment.NewLine + "Check if it's in the database" + Environment.NewLine + "Username:");
                                databaseCheckUser = ReadLine();
                                Write("Password:");
                                while (true)
                                {
                                    var key = System.Console.ReadKey(true);
                                    if (key.Key == ConsoleKey.Enter)
                                        break;
                                    databaseCheckPass += key.KeyChar;
                                }
                               
                                databaseCheckPass = GenerateSHA512String(databaseCheckPass);
                                RETRY:
                                bool found = false;
                                while (reader3.Read())
                                {
                                    string compare = reader3.GetString(0);
                                    compare = compare.Substring(128, 128);
                                    string usernameCOMPARE = reader3.GetString(1);
                                    
                                    if ((compare.Length == databaseCheckPass.Length) && (databaseCheckUser == usernameCOMPARE))
                                    {
                                        int i = 0;
                                        while ((i < compare.Length) && (compare[i] == databaseCheckPass[i]))
                                        {
                                            i += 1;
                                        }
                                        if (i == compare.Length)
                                        {
                                            found = true;
                                        }
                                    }
                                    if (found)
                                    {
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine("\nAccess Granted");
                                        Console.ForegroundColor = ConsoleColor.Gray;
                                        goto RETRYNEW;
                                    }
                                    else
                                    {
                                        goto RETRY;
                                    }
                                }

                                reader3.Close();
                                noah.Close();
                                if (found)
                                {
                                    goto RETRYNEW;
                                }
                                else
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("\nAccess Denied");
                                    Console.ForegroundColor = ConsoleColor.Gray;
                                    goto LOGIN3;
                                }
                            }
                            else
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                noah.Close();
                                WriteLine("\nSorry you've exhausted your numbear of attempts\n Closing console GOOD BYE!!!");
                                break;
                            }
                        }
                    };                                
                }
                // Keep Console Window Open
                if (Debugger.IsAttached){
                    Console.WriteLine("Press enter to exit...");
                    Console.ReadLine();
                }
            }
            // Random String Method for Salt
            string RandomString(int length)
            {
                const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
                StringBuilder res = new StringBuilder();
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    byte[] uintBuffer = new byte[sizeof(uint)];

                    while (length-- > 0)
                    {
                        rng.GetBytes(uintBuffer);
                        uint num = BitConverter.ToUInt32(uintBuffer, 0);
                        res.Append(valid[(int)(num % (uint)valid.Length)]);
                    }
                }

                return res.ToString();
            }

            //**********************************************ENCRYPT MD5**************************************//
            #region
            string GetMd5Hash(MD5 md5Hash, string input)
            {
                // Convert the input string to a byte array and compute the hash.
                byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
                // Create a new Stringbuilder to collect the bytes
                // and create a string.
                StringBuilder sBuilder = new StringBuilder();
                // Loop through each byte of the hashed data 
                // and format each one as a hexadecimal string.
                for (int i = 0; i < data.Length; i++)
                {
                    sBuilder.Append(data[i].ToString("x2"));
                }
                // Return the hexadecimal string.
                return sBuilder.ToString();
            }
            #endregion
            //******************************************END ENCRYPT MD5**************************************//


            //******************************************ENCRYPT WITH AES*************************************//
            #region
            string EncryptText(string input, string password)
            {
                // Get the bytes of the string
                byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(input);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

                // Hash the password with SHA256
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

                string result = Convert.ToBase64String(bytesEncrypted);

                return result;
            }
            string DecryptText(string input, string password)
            {
                // Get the bytes of the string
                byte[] bytesToBeDecrypted = Convert.FromBase64String(input);
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                passwordBytes = SHA256.Create().ComputeHash(passwordBytes);

                byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

                string result = Encoding.UTF8.GetString(bytesDecrypted);

                return result;
            }

            byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
            {
                byte[] encryptedBytes = null;

                // Set your salt here, change it to meet your flavor:
                // The salt bytes must be at least 8 bytes.
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                        AES.KeySize = 256;
                        AES.BlockSize = 128;

                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = key.GetBytes(AES.BlockSize / 8);

                        AES.Mode = CipherMode.CBC;

                        using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                            cs.Close();
                        }
                        encryptedBytes = ms.ToArray();
                    }
                }

                return encryptedBytes;
            }
            byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
            {
                byte[] decryptedBytes = null;

                // Set your salt here, change it to meet your flavor:
                // The salt bytes must be at least 8 bytes.
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
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
                }

                return decryptedBytes;
            }

            #endregion
            //**************************************END ENCRYPT WITH AES*************************************//


            //**************************************ENCRYPT WITH SHA512*************************************//
            #region
            string GenerateSHA512String(string inputString)
                {
                SHA512 sha512 = SHA512Managed.Create();
                byte[] bytes = Encoding.UTF8.GetBytes(inputString);
                byte[] hash = sha512.ComputeHash(bytes);
                return GetStringFromHash(hash);
                }

                string GetStringFromHash(byte[] hash)
                {
                StringBuilder result = new StringBuilder();
                for (int i = 0; i < hash.Length; i++)
                {
                    result.Append(hash[i].ToString("X2"));
                }
                return result.ToString();
                }
            #endregion
            //**************************************END ENCRYPT WITH SHA512*********************************//
        }
    }
}
