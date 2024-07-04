using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public static string StringToHex(string input)
        {
            string output = string.Concat(input.Select(c => ((int)c).ToString("x2")));
            output = output.ToLower();
            return output;
        }
        public static string HexToString(string hex)
        {
            string result = "";
            for (int i = 0; i < hex.Length; i += 2)
            {
                string hexPair = hex.Substring(i, 2);
                int charValue = Convert.ToInt32(hexPair, 16);
                char charFromHex = Convert.ToChar(charValue);
                result += charFromHex;
            }
            return result;
        }
        public override string Decrypt(string cipherText, string key)
        {
            bool hex = false;

            string PT = "";
            if (key[0] == '0' && key[1] == 'x')
            {
                key = key.Substring(2, 8);
                cipherText = cipherText.Substring(2, 8);
                hex = true;
                key = HexToString(key);
                cipherText = HexToString(cipherText);
            }

            List<int> S = new List<int>();
            List<char> T = new List<char>();
            for (int i = 0; i < 256; i++)
            {
                S.Add(i);
            }
            string tRep = "";
            while (tRep.Length < 256)
            {
                tRep = tRep.Insert(tRep.Length, key);
            }

            for (int i = 0; i < tRep.Length; i++)
            {
                T.Add(tRep[i]);
            }
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            int n = 0, k = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                n = (n + 1) % 256;
                k = (k + S[n]) % 256;
                int temp = S[n];
                S[n] = S[k];
                S[k] = temp;
                int t = (S[n] + S[k]) % 256;
                int v = S[t];
                int result = cipherText[i] ^ v;
                PT = PT.Insert(PT.Length, ((char)result).ToString());
            }
            if (hex)
            {
                PT = StringToHex(PT);
                PT = "0x" + PT;
            }


            return PT;
        }

        public override string Encrypt(string plainText, string key)
        {
            bool hex = false;

            string CT = "";
            if (key[0] == '0' && key[1] == 'x')
            {
                key = key.Substring(2, 8);
                plainText = plainText.Substring(2, 8);
                hex = true;
                key = HexToString(key);
                plainText = HexToString(plainText);
            }

            List<int> S = new List<int>();
            List<char> T = new List<char>();
            for (int i = 0; i < 256; i++)
            {
                S.Add(i);
            }
            string tRep = "";
            while (tRep.Length < 256)
            {
                tRep = tRep.Insert(tRep.Length, key);
            }

            for (int i = 0; i < tRep.Length; i++)
            {
                T.Add(tRep[i]);
            }
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }
            int n = 0, k = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                n = (n + 1) % 256;
                k = (k + S[n]) % 256;
                int temp = S[n];
                S[n] = S[k];
                S[k] = temp;
                int t = (S[n] + S[k]) % 256;
                int v = S[t];
                int result = plainText[i] ^ v;
                CT = CT.Insert(CT.Length, ((char)result).ToString());
            }
            if (hex)
            {
                CT = StringToHex(CT);
                CT = "0x" + CT;
            }


            return CT;
        }
    }
}
