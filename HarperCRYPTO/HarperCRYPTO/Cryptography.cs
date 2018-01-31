using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Configuration;

namespace HarperCRYPTO
{
    public class Cryptography
    {
        public readonly static string Salt = ConfigurationManager.AppSettings["salt"];
        private static byte[] salt = Encoding.Default.GetBytes(Salt);
        private static Rfc2898DeriveBytes keyGenerator;
        private static byte[] key;
        private static byte[] iv;

        private static void SetKey()
        {
            keyGenerator = new Rfc2898DeriveBytes("REDACTED", salt);
            key = keyGenerator.GetBytes(16);
            iv = keyGenerator.GetBytes(16);


            string str = System.Text.Encoding.Default.GetString(key);
        }

        /// <summary>
        /// Determines whether or not clear text equals cipher text value when encrypted
        /// </summary>
        /// <param name="clearText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static bool IsMatch(string clearText, string cipherText)
        {
            return EncryptData(clearText) == cipherText;
        }

        /// <summary>
        /// Determines whether or not clear text equals cipher text value when encrypted
        /// </summary>
        /// <param name="clearText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static bool IsMatch(string clearText, string cipherText, string salt_in)
        {
            return EncryptData(clearText, salt_in) == cipherText;
        }

        /// <summary>
        /// Encrypts data for serialization
        /// </summary>
        /// <param name="clearText"></param>
        /// <returns></returns>
        public static string EncryptData(string clearText, string salt_in)
        {
            Rfc2898DeriveBytes _keyGenerator = new Rfc2898DeriveBytes("REDACTED", Encoding.Default.GetBytes(salt_in));
            byte[] _key = _keyGenerator.GetBytes(16);
            byte[] _iv = _keyGenerator.GetBytes(16);

            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            ICryptoTransform cryptoEncryptor = aesProvider.CreateEncryptor(_key, _iv);
            MemoryStream mStream = new MemoryStream();
            CryptoStream writerStream = new CryptoStream(mStream, cryptoEncryptor, CryptoStreamMode.Write);
            byte[] buffer = Encoding.Default.GetBytes(clearText);
            writerStream.Write(buffer, 0, buffer.Length);
            writerStream.FlushFinalBlock();
            byte[] cipherTextinBytes = mStream.ToArray();
            mStream.Close();
            writerStream.Close();
            return Convert.ToBase64String(cipherTextinBytes);
        }

        /// <summary>
        /// Encrypts data for serialization
        /// </summary>
        /// <param name="clearText"></param>
        /// <returns></returns>
        public static string EncryptData(string clearText)
        {
            SetKey();
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            ICryptoTransform cryptoEncryptor = aesProvider.CreateEncryptor(key, iv);
            MemoryStream mStream = new MemoryStream();
            CryptoStream writerStream = new CryptoStream(mStream, cryptoEncryptor, CryptoStreamMode.Write);
            byte[] buffer = Encoding.Default.GetBytes(clearText);
            writerStream.Write(buffer, 0, buffer.Length);
            writerStream.FlushFinalBlock();
            byte[] cipherTextinBytes = mStream.ToArray();
            mStream.Close();
            writerStream.Close();
            return Convert.ToBase64String(cipherTextinBytes);
        }
        
        /// <summary>
        /// Encrypts data for serialization
        /// </summary>
        /// <param name="clearText"></param>
        /// <returns></returns>
        public static string Encrypt256(string clearText)
        {
            key = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["256key"]);
            iv = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["iv"]);
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Mode = CipherMode.CBC;
            aesProvider.Padding = PaddingMode.Zeros;
            ICryptoTransform cryptoEncryptor = aesProvider.CreateEncryptor(key, iv);
            MemoryStream mStream = new MemoryStream();
            CryptoStream writerStream = new CryptoStream(mStream, cryptoEncryptor, CryptoStreamMode.Write);
            byte[] buffer = Encoding.Default.GetBytes(clearText);
            writerStream.Write(buffer, 0, buffer.Length);
            writerStream.FlushFinalBlock();
            byte[] cipherTextinBytes = mStream.ToArray();
            mStream.Close();
            writerStream.Close();
            return ByteArrayToHexString(cipherTextinBytes);
        }

        //no
        public static string Decrypt256FromB64(string cipherText)
        {
            key = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["256key"]);
            iv = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["iv"]);
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Mode = CipherMode.CBC;
            aesProvider.Padding = PaddingMode.Zeros;
            byte[] cipherTextBytesForDecrypt = Convert.FromBase64String(cipherText);
            ICryptoTransform cryptoDecryptor = aesProvider.CreateDecryptor(key, iv);
            MemoryStream memStreamEncryptData = new MemoryStream(cipherTextBytesForDecrypt);
            CryptoStream rStream = new CryptoStream(memStreamEncryptData, cryptoDecryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytesForDecrypt.Length];
            int decryptedByteCount = rStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memStreamEncryptData.Close();
            rStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        public static string Decrypt256FromHEX(string cipherText)
        {
            key = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["256key"]);
            iv = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["iv"]);
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            aesProvider.Mode = CipherMode.CBC;
            aesProvider.Padding = PaddingMode.Zeros;

            byte[] cipherTextBytesForDecrypt = HexStringToByteArray(cipherText);

            ICryptoTransform cryptoDecryptor = aesProvider.CreateDecryptor(key, iv);
            MemoryStream memStreamEncryptData = new MemoryStream(cipherTextBytesForDecrypt);
            CryptoStream rStream = new CryptoStream(memStreamEncryptData, cryptoDecryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytesForDecrypt.Length];
            int decryptedByteCount = rStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memStreamEncryptData.Close();
            rStream.Close();
            return Encoding.Default.GetString(plainTextBytes, 0, decryptedByteCount).Replace("\0", "");
        }

        public static string ByteArrayToHexString(byte[] input)
        {
            return BitConverter.ToString(input).Replace("-", "");
        }

        public static byte[] HexStringToByteArray(string strInput)
        {
            int numBytes = (strInput.Length) / 2;
            byte[] bytes = new byte[numBytes];
            for (int x = 0; x < numBytes; ++x)
            {
                bytes[x] = Convert.ToByte(strInput.Substring(x * 2, 2), 16);
            }
            return bytes;
        }

        /// <summary>
        /// Decrypts serialized data
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string DecryptData(string cipherText)
        {
            SetKey();
            AesCryptoServiceProvider aesProvider = new AesCryptoServiceProvider();
            byte[] cipherTextBytesForDecrypt = Convert.FromBase64String(cipherText);
            ICryptoTransform cryptoDecryptor = aesProvider.CreateDecryptor(key, iv);
            MemoryStream memStreamEncryptData = new MemoryStream(cipherTextBytesForDecrypt);
            CryptoStream rStream = new CryptoStream(memStreamEncryptData, cryptoDecryptor, CryptoStreamMode.Read);
            byte[] plainTextBytes = new byte[cipherTextBytesForDecrypt.Length];
            int decryptedByteCount = rStream.Read(plainTextBytes, 0, plainTextBytes.Length);
            memStreamEncryptData.Close();
            rStream.Close();
            return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
        }

        /// <summary>
        /// DEPRECATED - This method is not terribly secure, use Hash2/DeHash2 instead
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string LegacyHash(string value)
        {
            string Key = ConfigurationManager.AppSettings["hashkey"];
            System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

            byte[] b_key = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Key));
            string s_key = string.Empty;
            foreach (byte a in b_key)
            {
                if (a < 16)
                    s_key += "0" + a.ToString("x");
                else
                    s_key += a.ToString("x");
            }

            byte[] b_stamp = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.ToString("yyyyMMdd")));
            string s_stamp = string.Empty;
            foreach (byte a in b_stamp)
            {
                if (a < 16)
                    s_stamp += "0" + a.ToString("x");
                else
                    s_stamp += a.ToString("x");
            }

            string encvalue = System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value));
            return string.Format("{0}-{1}-{2}", 
                new object[] { 
                    s_key,
                    s_stamp,
                    encvalue});
        }

        /// <summary>
        /// DEPRECATED - This method is not terribly secure, use Hash2/DeHash2 instead
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string LegacyDeHash(string value)
        {
            string Key = ConfigurationManager.AppSettings["hashkey"];
            string ClearText = string.Empty;
            try
            {
                System.Security.Cryptography.MD5CryptoServiceProvider md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

                byte[] b_key = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(Key));
                string expectedkeyhash = string.Empty;
                foreach (byte a in b_key)
                {
                    if (a < 16)
                        expectedkeyhash += "0" + a.ToString("x");
                    else
                        expectedkeyhash += a.ToString("x");
                }
                string actualkeyhash = value.Split(System.Convert.ToChar("-"))[0];
                if (expectedkeyhash == actualkeyhash)
                {
                    byte[] b_stamp = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(DateTime.Now.ToString("yyyyMMdd")));
                    string expectedstamphash = string.Empty;
                    foreach (byte a in b_stamp)
                    {
                        if (a < 16)
                            expectedstamphash += "0" + a.ToString("x");
                        else
                            expectedstamphash += a.ToString("x");
                    }
                    string actualstamphash = value.Split(System.Convert.ToChar("-"))[1];
                    if (expectedstamphash==actualstamphash)
                    {
                        ClearText = System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(value.Split(System.Convert.ToChar("-"))[2]));
                    }
                }
            }
            catch
            {
                throw new ArgumentException("Unable to de-hash value");
            }
            return ClearText;
        }

        public static string Hash(string value)
        {
            return Hash(value, false);
        }
        public static string DeHash(string value)
        {
            return DeHash(value, false);
        }

        /// <summary>
        /// Replaces Hash/DeHash
        /// Hash
        /// - first piece was same for all users all days - never changes
        /// - second piece was same for all users on a given day
        /// 
        /// Hash2
        /// - first piece different for all users and changes every day
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string Hash(string value, bool use_legacy_algorithm)
        {
            if (use_legacy_algorithm)
            {
                return LegacyHash(value);
            }
            else
            {
                System.Threading.Thread.Sleep(1);
                string checkdigit = DateTime.Now.Millisecond.ToString();
                string s_key = 
                    GH(//md5
                        GHB(ConfigurationManager.AppSettings["hashkey"] 
                            + value 
                            + GR(checkdigit) //revers
                            + DateTime.Now.ToString("yyyyMMdd"))
                    );
                string encvalue = GB(value);
                string enccheckdigit = GB(checkdigit);

                return string.Format("{0}-{1}-{2}",
                    new object[] { 
                    s_key,
                    encvalue,
                    enccheckdigit
                });
            }
        }

        /// <summary>
        /// Replaces Hash/DeHash
        /// Hash
        /// - first piece was same for all users all days - never changes
        /// - second piece was same for all users on a given day
        /// 
        /// Hash2
        /// - first piece different for all users and changes every day
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        public static string DeHash(string value, bool use_legacy_algorithm)
        {
            if (use_legacy_algorithm)
            {
                return LegacyDeHash(value);
            }
            else
            {
                string ReturnString = string.Empty;
                try
                {
                    string actualvalue = GU(value.Split(System.Convert.ToChar("-"))[1]);
                    string checkdigit = GU(value.Split(System.Convert.ToChar("-"))[2]);
                    string expectedkeyhash = GH(GHB(ConfigurationManager.AppSettings["hashkey"] + actualvalue + GR(checkdigit) + DateTime.Now.ToString("yyyyMMdd")));
                    string actualkeyhash = value.Split(System.Convert.ToChar("-"))[0];
                    if (expectedkeyhash == actualkeyhash)
                    {
                        ReturnString = actualvalue;
                    }
                }
                catch
                {
                    throw new ArgumentException("Unable to de-hash value");
                }
                return ReturnString;
            }
        }

        private static string GU(string value) 
        {
            return System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(value));        
        }
        private static string GB(string value) 
        {
            return System.Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(value));
        }
        public static string GH(byte[] value)
        {
            string response = string.Empty;
            foreach (byte a in value)
            {
                if (a < 16)
                    response += "0" + a.ToString("x");
                else
                    response += a.ToString("x");
            }
            return response;
        }
        private static byte[] GHB(string value)
        {
            return new System.Security.Cryptography.MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.UTF8.GetBytes(value));
        }
        private static string GR(string value)
        {
            char[] arr = value.ToCharArray();
            Array.Reverse(arr);
            return new string(arr);
        }
    }
}
