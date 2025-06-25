using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace Danchi.Security
{
    public class PasswordEncripter : IPasswordEncripter
    {
        public string Decript(string value, List<byte[]> hash)
        {
            if (hash.Count < 2)
                throw new ArgumentException("Se deben especificar 2 hash, para Key y IV");


            byte[] cipherTextBytes = Convert.FromBase64String(value);
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            using (Rijndael rijndael = Rijndael.Create())
            using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(hash[0], hash[1]), CryptoStreamMode.Read))
            {
                int decrypterByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                return Encoding.UTF8.GetString(plainTextBytes, 0, decrypterByteCount);
            }
        }

        public string Encript(string value, out List<byte[]> hashes)
        {
            using (var rijndael = Rijndael.Create())
            {
                hashes = new List<byte[]>(2);
                rijndael.GenerateKey();
                hashes.Add(rijndael.Key);
                rijndael.GenerateIV();
                hashes.Add(rijndael.IV);
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plainMessageBytes = UTF8Encoding.UTF8.GetBytes(value);
                    cryptoStream.Write(plainMessageBytes, 0, plainMessageBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] cipherMessageBytes = memoryStream.ToArray();
                    return Convert.ToBase64String(cipherMessageBytes);
                }
            }
        }

        public string Encript(string value, List<byte[]> hashes)
        {
            if (hashes.Count < 2)
                throw new ArgumentException("Se deben especificar 2 hash, para Key y IV");
            using (var rijndael = Rijndael.Create())
            {
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(hashes[0], hashes[1]), CryptoStreamMode.Write))
                {
                    byte[] plainMessageBytes = UTF8Encoding.UTF8.GetBytes(value);
                    cryptoStream.Write(plainMessageBytes, 0, plainMessageBytes.Length);
                    cryptoStream.FlushFinalBlock();
                    byte[] cipherMessageBytes = memoryStream.ToArray();
                    return Convert.ToBase64String(cipherMessageBytes);
                }
            }
        }
    }
}