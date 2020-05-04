using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace lab3
{
    static class RSANet
    {
        static int encodingSize = 2;
        static public int blockSize = 224;

        public static string BytesToString(byte[] data)
        {
            if (data.Length % encodingSize != 0)
                throw new Exception("Длина массива data не кратна размеру одного символа");

            StringBuilder result = new StringBuilder(data.Length / encodingSize);
            for (int i = 0; i < data.Length; i += encodingSize)
            {
                char ch = (char)((data[i] << 8) + data[i + 1]);
                result.Append(ch);
            }

            return result.ToString();
        }

        public static byte[] StringToBytes(string data)
        {
            byte[] result = new byte[data.Length * encodingSize];

            for (int i = 0; i < data.Length; i++)
            {
                result[i * encodingSize] = (byte)(data[i] >> 8);
                result[i * encodingSize + 1] = (byte)(data[i] ^ (data[i] >> 8 << 8));
            }

            return result;
        }

        public static byte[] Encrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
                }
                return encryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public static byte[] Decrypt(byte[] DataToDecrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            try
            {
                byte[] decryptedData;
                using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
                {
                    RSA.ImportParameters(RSAKeyInfo);
                    decryptedData = RSA.Decrypt(DataToDecrypt, DoOAEPPadding);
                }
                return decryptedData;
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.ToString());
                return null;
            }
        }
    }
}
