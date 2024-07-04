using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public List<KeyValuePair<string, string>> CD = new List<KeyValuePair<string, string>>();
        public List<KeyValuePair<string, string>> LR = new List<KeyValuePair<string, string>>();
        public List<string> keys = new List<string>();
        // dividing the string into 2 devisions left and right every devision with 32 bits
        public string generate_LR(string plainText)
        {
            string IP = create_IP(plainText);
            string L0 = IP.Substring(0, 32);
            string R0 = IP.Substring(32, 32);
            LR.Add(new KeyValuePair<string, string>(L0, R0));

            for (int i = 1; i <= 16; i++)
            {
                string L = LR[i - 1].Value;
                string R = get_R(LR[i - 1].Key, LR[i - 1].Value, keys[i]);
                LR.Add(new KeyValuePair<string, string>(L, R));
            }
            //doing the intial permutation

            string RL = LR[16].Value + LR[16].Key;
            int[] IP_1 = new int[64] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
            string final = "";
            for (int i = 0; i < 64; i++)
                final += RL[IP_1[i] - 1];

            string cipherText = "0x" + Convert.ToInt64(final, 2).ToString("X");

            return cipherText;
        }
        //expanding the R then doing xor then doing s-boxes technique

        public string get_R(string Left, string Right, string k)
        {
            string ER = expand(Right);
            string tmp_f = X_OR(ER, k);
            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };


            List<string> Blocks = new List<string>();

            int cnt = 0;
            string tmp_B = "";
            for (int i = 0; i < tmp_f.Length; i++)
            {
                if (cnt == 6)
                {
                    Blocks.Add(tmp_B);
                    tmp_B = "";
                    cnt = 0;
                }
                tmp_B += tmp_f[i];
                cnt++;
            }
            Blocks.Add(tmp_B);
            string s = "";
            for (int i = 0; i < Blocks.Count; i++)
            {
                int row = get_pos((Blocks[i][0].ToString() + Blocks[i][5].ToString()));
                int col = get_pos((Blocks[i].Substring(1, 4)).ToString());
                int sb = 0;
                if (i == 0)
                    sb = s1[row, col];
                if (i == 1)
                    sb = s2[row, col];
                if (i == 2)
                    sb = s3[row, col];
                if (i == 3)
                    sb = s4[row, col];
                if (i == 4)
                    sb = s5[row, col];
                if (i == 5)
                    sb = s6[row, col];
                if (i == 6)
                    sb = s7[row, col];
                if (i == 7)
                    sb = s8[row, col];
                s += ToBinary(sb).ToString();
            }

            int[] P = new int[32] { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
            string f = "";

            for (int i = 0; i < 32; i++)
                f += s[P[i] - 1];

            string New_R = X_OR(Left, f);
            return New_R;
        }
        //defining a function to turn integers into binary
        public string ToBinary(int n)
        {
            Dictionary<int, string> dict = new Dictionary<int, string>();
            dict.Add(0, "0000");
            dict.Add(1, "0001");
            dict.Add(2, "0010");
            dict.Add(3, "0011");
            dict.Add(4, "0100");
            dict.Add(5, "0101");
            dict.Add(6, "0110");
            dict.Add(7, "0111");
            dict.Add(8, "1000");
            dict.Add(9, "1001");
            dict.Add(10, "1010");
            dict.Add(11, "1011");
            dict.Add(12, "1100");
            dict.Add(13, "1101");
            dict.Add(14, "1110");
            dict.Add(15, "1111");
            return dict[n];
        }
        public int get_pos(string pos)
        {
            int ans = 0;
            int idx = 0;
            for (int i = pos.Length - 1; i >= 0; i--)
                ans += ((int)Math.Pow(2, idx++) * (pos[i] - '0'));
            return ans;
        }
        //function responsable of expanding the right to 48 bits

        public string expand(string R)
        {
            int[] E = new int[48] { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
            string New_R = "";
            for (int i = 0; i < 48; i++)
                New_R += R[E[i] - 1];
            return New_R;
        }
        //xoring the 2 strings to get the xored right
        public string X_OR(string a, string b)
        {
            string res = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i])
                    res += '0';
                else
                    res += '1';
            }
            return res;
        }
        public string swap_1(string s)
        {
            char c = s[0];
            string res = "";
            for (int i = 1; i < s.Length; i++)
                res += s[i];
            res += c;
            return res;
        }
        public string swap_2(string s)
        {
            char c1 = s[0], c2 = s[1];
            string res = "";
            for (int i = 2; i < s.Length; i++)
                res += s[i];
            res += c1;
            res += c2;
            return res;
        }
        //generating the C&D
        public void generate_CD(string key)
        {
            string tmp = binary(key);
            string New_key = get_key(tmp);
            string C0 = New_key.Substring(0, 28);
            string D0 = New_key.Substring(28, 28);
            keys.Add(generate_key(C0 + D0));
            CD.Add(new KeyValuePair<string, string>(C0, D0));
            for (int i = 1; i <= 16; i++)
            {
                if (i == 1 || i == 2 || i == 9 || i == 16)
                {
                    string tmp1 = swap_1(CD[i - 1].Key);
                    string tmp2 = swap_1(CD[i - 1].Value);
                    CD.Add(new KeyValuePair<string, string>(tmp1, tmp2));
                    keys.Add(generate_key(tmp1 + tmp2));
                }
                else
                {
                    string tmp1 = swap_2(CD[i - 1].Key);
                    string tmp2 = swap_2(CD[i - 1].Value);
                    CD.Add(new KeyValuePair<string, string>(tmp1, tmp2));
                    keys.Add(generate_key(tmp1 + tmp2));
                }
            }
        }
        public string get_key(string key)
        {
            int[] PC1 = new int[56] { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
            string New_key = "";
            for (int i = 0; i < 56; i++)
                New_key += key[PC1[i] - 1];
            return New_key;
        }
        public string generate_key(string key)
        {
            int[] PC2 = new int[48] { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
            string New_key = "";
            for (int i = 0; i < 48; i++)
                New_key += key[PC2[i] - 1];
            return New_key;
        }
        //changing the hexa to binary
        public string binary(string hexa)
        {
            Dictionary<char, string> data = new Dictionary<char, string>();
            data.Add('0', "0000");
            data.Add('1', "0001");
            data.Add('2', "0010");
            data.Add('3', "0011");
            data.Add('4', "0100");
            data.Add('5', "0101");
            data.Add('6', "0110");
            data.Add('7', "0111");
            data.Add('8', "1000");
            data.Add('9', "1001");
            data.Add('A', "1010");
            data.Add('B', "1011");
            data.Add('C', "1100");
            data.Add('D', "1101");
            data.Add('E', "1110");
            data.Add('F', "1111");
            string result = "";
            for (int i = 2; i < hexa.Length; i++)
                result += data[hexa[i]];
            return result;
        }
        //creating the intial permutation for the string
        public string create_IP(string M)
        {
            int[] IP = new int[64] { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
            string temp = binary(M);
            string New_M = "";
            for (int i = 0; i < 64; i++)
                New_M += temp[IP[i] - 1];
            return New_M;
        }
        // changing the binary to hexa
        public static string TOHEXA(string n)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            dict.Add("0000", "0");
            dict.Add("0001", "1");
            dict.Add("0010", "2");
            dict.Add("0011", "3");
            dict.Add("0100", "4");
            dict.Add("0101", "5");
            dict.Add("0110", "6");
            dict.Add("0111", "7");
            dict.Add("1000", "8");
            dict.Add("1001", "9");
            dict.Add("1010", "A");
            dict.Add("1011", "B");
            dict.Add("1100", "C");
            dict.Add("1101", "D");
            dict.Add("1110", "E");
            dict.Add("1111", "F");
            return dict[n];
        }
        public string generate_LR2(string CT)
        {
            string IP = create_IP(CT);
            string L0 = IP.Substring(0, 32);
            string R0 = IP.Substring(32, 32);
            LR.Add(new KeyValuePair<string, string>(L0, R0));
            for (int i = 1; i <= 16; i++)
            {
                string L = LR[i - 1].Value;
                string R = get_R(LR[i - 1].Key, LR[i - 1].Value, keys[keys.Count - i]);
                LR.Add(new KeyValuePair<string, string>(L, R));
            }
            string RL = LR[16].Value + LR[16].Key;
            int[] IP_1 = new int[64] { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
            string final = "";
            for (int i = 0; i < 64; i++)
                final += RL[IP_1[i] - 1];
            string plain = "0x";
            for (int i = 0; i < 64; i += 4)
            {
                string temp = TOHEXA(final.Substring(i, 4));
                plain += temp;
            }
            return plain;
        }
        //main functions for decryption and encryption
        public override string Decrypt(string cipherText, string key)
        {
            keys.Clear();
            LR.Clear();

            generate_CD(key);
            return generate_LR2((cipherText));
        }
        public override string Encrypt(string plainText, string key)
        {
            keys.Clear();
            LR.Clear();
            generate_CD(key);
            return generate_LR(plainText);
        }
    }
}
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Text;
//using System.Threading.Tasks;

//namespace SecurityLibrary.DES
//{
//    /// <summary>
//    /// If the string starts with 0x.... then it's Hexadecimal not string
//    /// </summary>
//    public class DES : CryptographicTechnique
//    {
//        public override string Decrypt(string cipherText, string key)
//        { 
//            // string mainPlain = "0x0123456789ABCDEF";
//            string binaryMainCipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2);
//            string tempCipher = "";

//            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
//            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
//            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
//            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
//            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
//            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
//            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
//            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };



//            for (int i = 0; i < 64 - binaryMainCipher.Length; i++)
//            {
//                tempCipher = tempCipher.Insert(tempCipher.Length, "0");
//            }
//            binaryMainCipher = tempCipher + binaryMainCipher;
//            string binaryMainKey = Convert.ToString(Convert.ToInt64(key, 16), 2);
//            string tempKey = "";
//            for (int i = 0; i < 64 - binaryMainKey.Length; i++)
//            {
//                tempKey = tempKey.Insert(tempKey.Length, "0");
//            }
//            binaryMainKey = tempKey + binaryMainKey;
//            Dictionary<int, char> PC_1Map = new Dictionary<int, char>();
//            {
//                PC_1Map[1] = binaryMainKey[56];
//                PC_1Map[2] = binaryMainKey[48];
//                PC_1Map[3] = binaryMainKey[40];
//                PC_1Map[4] = binaryMainKey[32];
//                PC_1Map[5] = binaryMainKey[24];
//                PC_1Map[6] = binaryMainKey[16];
//                PC_1Map[7] = binaryMainKey[8];
//                PC_1Map[8] = binaryMainKey[0];
//                PC_1Map[9] = binaryMainKey[57];
//                PC_1Map[10] = binaryMainKey[49];
//                PC_1Map[11] = binaryMainKey[41];
//                PC_1Map[12] = binaryMainKey[33];
//                PC_1Map[13] = binaryMainKey[25];
//                PC_1Map[14] = binaryMainKey[17];
//                PC_1Map[15] = binaryMainKey[9];
//                PC_1Map[16] = binaryMainKey[1];
//                PC_1Map[17] = binaryMainKey[58];
//                PC_1Map[18] = binaryMainKey[50];
//                PC_1Map[19] = binaryMainKey[42];
//                PC_1Map[20] = binaryMainKey[34];
//                PC_1Map[21] = binaryMainKey[26];
//                PC_1Map[22] = binaryMainKey[18];
//                PC_1Map[23] = binaryMainKey[10];
//                PC_1Map[24] = binaryMainKey[2];
//                PC_1Map[25] = binaryMainKey[59];
//                PC_1Map[26] = binaryMainKey[51];
//                PC_1Map[27] = binaryMainKey[43];
//                PC_1Map[28] = binaryMainKey[35];
//                PC_1Map[29] = binaryMainKey[62];
//                PC_1Map[30] = binaryMainKey[54];
//                PC_1Map[31] = binaryMainKey[46];
//                PC_1Map[32] = binaryMainKey[38];
//                PC_1Map[33] = binaryMainKey[30];
//                PC_1Map[34] = binaryMainKey[22];
//                PC_1Map[35] = binaryMainKey[14];
//                PC_1Map[36] = binaryMainKey[6];
//                PC_1Map[37] = binaryMainKey[61];
//                PC_1Map[38] = binaryMainKey[55];
//                PC_1Map[39] = binaryMainKey[45];
//                PC_1Map[40] = binaryMainKey[37];
//                PC_1Map[41] = binaryMainKey[29];
//                PC_1Map[42] = binaryMainKey[21];
//                PC_1Map[43] = binaryMainKey[13];
//                PC_1Map[44] = binaryMainKey[5];
//                PC_1Map[45] = binaryMainKey[60];
//                PC_1Map[46] = binaryMainKey[52];
//                PC_1Map[47] = binaryMainKey[44];
//                PC_1Map[48] = binaryMainKey[36];
//                PC_1Map[49] = binaryMainKey[28];
//                PC_1Map[50] = binaryMainKey[20];
//                PC_1Map[51] = binaryMainKey[12];
//                PC_1Map[52] = binaryMainKey[4];
//                PC_1Map[53] = binaryMainKey[27];
//                PC_1Map[54] = binaryMainKey[19];
//                PC_1Map[55] = binaryMainKey[11];
//                PC_1Map[56] = binaryMainKey[3];
//            }
//            List<char> C0 = new List<char>();
//            List<char> D0 = new List<char>();
//            for (int i = 1; i <= 28; i++)
//            {
//                C0.Add(PC_1Map[i]);
//            }
//            for (int i = 29; i <= 56; i++)
//            {
//                D0.Add(PC_1Map[i]);
//            }
//            List<char> tempc = new List<char>();
//            List<char> tempd = new List<char>();
//            for (int i = 0; i < 28; i++)
//            {
//                tempc.Add(C0[i]);
//            }

//            for (int i = 0; i < 28; i++)
//            {
//                tempd.Add(D0[i]);
//            }
//            List<List<char>> keys = new List<List<char>>();
//            Dictionary<int, char> k1_map = new Dictionary<int, char>();
//            char temp1 = tempc[0];
//            for (int i = 0; i < 28; i++)
//            {
//                if (i == 27)
//                {
//                    tempc[i] = temp1;
//                }
//                else
//                {
//                    tempc[i] = tempc[i + 1];
//                }
//            }
//            char temp2 = tempd[0];
//            for (int i = 0; i < 28; i++)
//            {

//                if (i == 27)
//                {
//                    tempd[i] = temp2;
//                }
//                else
//                {
//                    tempd[i] = tempd[i + 1];
//                }
//            }
//            k1_map.Clear();
//            List<char> temp = new List<char>();
//            for (int i = 0; i < tempc.Count; i++) temp.Add(tempc[i]);
//            temp.AddRange(tempd);
//            {
//                k1_map[1] = temp[13];
//                k1_map[2] = temp[13];
//                k1_map[3] = temp[10];
//                k1_map[4] = temp[23];
//                k1_map[5] = temp[0];
//                k1_map[6] = temp[4];
//                k1_map[7] = temp[2];
//                k1_map[8] = temp[27];
//                k1_map[9] = temp[14];
//                k1_map[10] = temp[5];
//                k1_map[11] = temp[20];
//                k1_map[12] = temp[9];
//                k1_map[13] = temp[22];
//                k1_map[14] = temp[18];
//                k1_map[15] = temp[11];
//                k1_map[16] = temp[3];
//                k1_map[17] = temp[25];
//                k1_map[18] = temp[7];
//                k1_map[19] = temp[15];
//                k1_map[20] = temp[6];
//                k1_map[21] = temp[26];
//                k1_map[22] = temp[19];
//                k1_map[23] = temp[12];
//                k1_map[24] = temp[1];
//                k1_map[25] = temp[40];
//                k1_map[26] = temp[51];
//                k1_map[27] = temp[30];
//                k1_map[28] = temp[36];
//                k1_map[29] = temp[46];
//                k1_map[30] = temp[54];
//                k1_map[31] = temp[29];
//                k1_map[32] = temp[39];
//                k1_map[33] = temp[50];
//                k1_map[34] = temp[44];
//                k1_map[35] = temp[32];
//                k1_map[36] = temp[47];
//                k1_map[37] = temp[43];
//                k1_map[38] = temp[48];
//                k1_map[39] = temp[38];
//                k1_map[40] = temp[55];
//                k1_map[41] = temp[33];
//                k1_map[42] = temp[52];
//                k1_map[43] = temp[45];
//                k1_map[44] = temp[41];
//                k1_map[45] = temp[49];
//                k1_map[46] = temp[35];
//                k1_map[47] = temp[28];
//                k1_map[48] = temp[31];
//            }
//            List<char> k = new List<char>();
//            foreach (var val in k1_map.Values) k.Add(val);
//            keys.Add(k);

//            int iter = 1;
//            while (iter < 16)
//            {
//                temp1 = tempc[0];
//                for (int i = 0; i < 28; i++)
//                {
//                    if (i == 27)
//                    {
//                        tempc[i] = temp1;
//                    }
//                    else
//                    {
//                        tempc[i] = tempc[i + 1];
//                    }
//                }
//                temp2 = tempd[0];
//                for (int i = 0; i < 28; i++)
//                {

//                    if (i == 27)
//                    {
//                        tempd[i] = temp2;
//                    }
//                    else
//                    {
//                        tempd[i] = tempd[i + 1];
//                    }
//                }
//                if (iter == 2 || iter == 3 || iter == 4 || iter == 5 || iter == 6 || iter == 7
//                    || iter == 9 || iter == 10 || iter == 11 || iter == 12 || iter == 13 || iter == 14)
//                {
//                    temp1 = tempc[0];
//                    for (int i = 0; i < 28; i++)
//                    {
//                        if (i == 27)
//                        {
//                            tempc[i] = temp1;
//                        }
//                        else
//                        {
//                            tempc[i] = tempc[i + 1];
//                        }
//                    }
//                    temp2 = tempd[0];
//                    for (int i = 0; i < 28; i++)
//                    {

//                        if (i == 27)
//                        {
//                            tempd[i] = temp2;
//                        }
//                        else
//                        {
//                            tempd[i] = tempd[i + 1];
//                        }
//                    }
//                }
//                temp = new List<char>();
//                for (int i = 0; i < tempc.Count; i++) temp.Add(tempc[i]);
//                temp.AddRange(tempd);
//                {
//                    k1_map[1] = temp[13];
//                    k1_map[2] = temp[16];
//                    k1_map[3] = temp[10];
//                    k1_map[4] = temp[23];
//                    k1_map[5] = temp[0];
//                    k1_map[6] = temp[4];
//                    k1_map[7] = temp[2];
//                    k1_map[8] = temp[27];
//                    k1_map[9] = temp[14];
//                    k1_map[10] = temp[5];
//                    k1_map[11] = temp[20];
//                    k1_map[12] = temp[9];
//                    k1_map[13] = temp[22];
//                    k1_map[14] = temp[18];
//                    k1_map[15] = temp[11];
//                    k1_map[16] = temp[3];
//                    k1_map[17] = temp[25];
//                    k1_map[18] = temp[7];
//                    k1_map[19] = temp[15];
//                    k1_map[20] = temp[6];
//                    k1_map[21] = temp[26];
//                    k1_map[22] = temp[19];
//                    k1_map[23] = temp[12];
//                    k1_map[24] = temp[1];
//                    k1_map[25] = temp[40];
//                    k1_map[26] = temp[51];
//                    k1_map[27] = temp[30];
//                    k1_map[28] = temp[36];
//                    k1_map[29] = temp[46];
//                    k1_map[30] = temp[54];
//                    k1_map[31] = temp[29];
//                    k1_map[32] = temp[39];
//                    k1_map[33] = temp[50];
//                    k1_map[34] = temp[44];
//                    k1_map[35] = temp[32];
//                    k1_map[36] = temp[47];
//                    k1_map[37] = temp[43];
//                    k1_map[38] = temp[48];
//                    k1_map[39] = temp[38];
//                    k1_map[40] = temp[55];
//                    k1_map[41] = temp[33];
//                    k1_map[42] = temp[52];
//                    k1_map[43] = temp[45];
//                    k1_map[44] = temp[41];
//                    k1_map[45] = temp[49];
//                    k1_map[46] = temp[35];
//                    k1_map[47] = temp[28];
//                    k1_map[48] = temp[31];
//                }
//                k = new List<char>();
//                foreach (var val in k1_map.Values) k.Add(val);
//                keys.Add(k);


//                iter++;

//            }
//            //foreach (var val in keys)
//            //{

//            //    for (int i = 0; i < val.Count; i++)
//            //    {
//            //        Console.Write(val[i]);
//            //    }
//            //    Console.WriteLine();
//            //}



//            SortedDictionary<int, char> R16L16Map = new SortedDictionary<int, char>();
//            {
//                R16L16Map[40] = binaryMainCipher[0];
//                R16L16Map[8] = binaryMainCipher[1];
//                R16L16Map[48] = binaryMainCipher[2];
//                R16L16Map[16] = binaryMainCipher[3];
//                R16L16Map[56] = binaryMainCipher[4];
//                R16L16Map[24] = binaryMainCipher[5];
//                R16L16Map[64] = binaryMainCipher[6];
//                R16L16Map[32] = binaryMainCipher[7];
//                R16L16Map[39] = binaryMainCipher[8];
//                R16L16Map[7] = binaryMainCipher[9];
//                R16L16Map[47] = binaryMainCipher[10];
//                R16L16Map[15] = binaryMainCipher[11];
//                R16L16Map[55] = binaryMainCipher[12];
//                R16L16Map[23] = binaryMainCipher[13];
//                R16L16Map[63] = binaryMainCipher[14];
//                R16L16Map[31] = binaryMainCipher[15];
//                R16L16Map[38] = binaryMainCipher[16];
//                R16L16Map[6] = binaryMainCipher[17];
//                R16L16Map[46] = binaryMainCipher[18];
//                R16L16Map[14] = binaryMainCipher[19];
//                R16L16Map[54] = binaryMainCipher[20];
//                R16L16Map[22] = binaryMainCipher[21];
//                R16L16Map[62] = binaryMainCipher[22];
//                R16L16Map[30] = binaryMainCipher[23];
//                R16L16Map[37] = binaryMainCipher[24];
//                R16L16Map[5] = binaryMainCipher[25];
//                R16L16Map[45] = binaryMainCipher[26];
//                R16L16Map[13] = binaryMainCipher[27];
//                R16L16Map[53] = binaryMainCipher[28];
//                R16L16Map[21] = binaryMainCipher[29];
//                R16L16Map[61] = binaryMainCipher[30];
//                R16L16Map[29] = binaryMainCipher[31];
//                R16L16Map[36] = binaryMainCipher[32];
//                R16L16Map[4] = binaryMainCipher[33];
//                R16L16Map[44] = binaryMainCipher[34];
//                R16L16Map[12] = binaryMainCipher[35];
//                R16L16Map[52] = binaryMainCipher[36];
//                R16L16Map[20] = binaryMainCipher[37];
//                R16L16Map[60] = binaryMainCipher[38];
//                R16L16Map[28] = binaryMainCipher[39];
//                R16L16Map[35] = binaryMainCipher[40];
//                R16L16Map[3] = binaryMainCipher[41];
//                R16L16Map[43] = binaryMainCipher[42];
//                R16L16Map[11] = binaryMainCipher[43];
//                R16L16Map[51] = binaryMainCipher[44];
//                R16L16Map[19] = binaryMainCipher[45];
//                R16L16Map[59] = binaryMainCipher[46];
//                R16L16Map[27] = binaryMainCipher[47];
//                R16L16Map[34] = binaryMainCipher[48];
//                R16L16Map[2] = binaryMainCipher[49];
//                R16L16Map[42] = binaryMainCipher[50];
//                R16L16Map[10] = binaryMainCipher[51];
//                R16L16Map[50] = binaryMainCipher[52];
//                R16L16Map[18] = binaryMainCipher[53];
//                R16L16Map[58] = binaryMainCipher[54];
//                R16L16Map[26] = binaryMainCipher[55];
//                R16L16Map[33] = binaryMainCipher[56];
//                R16L16Map[1] = binaryMainCipher[57];
//                R16L16Map[41] = binaryMainCipher[58];
//                R16L16Map[9] = binaryMainCipher[59];
//                R16L16Map[49] = binaryMainCipher[60];
//                R16L16Map[17] = binaryMainCipher[61];
//                R16L16Map[57] = binaryMainCipher[62];
//                R16L16Map[25] = binaryMainCipher[63];
//            }
//            List<char> R16L16 = new List<char>();
//            foreach (var val in R16L16Map.Values)
//            {
//                R16L16.Add(val);
//            }
//            List<char> Left = new List<char>();
//            List<char> right = new List<char>();
//            for (int i = 0; i < 32; i++)
//            {
//                right.Add(R16L16[i]);
//            }
//            for (int i = 32; i < 64; i++)
//            {
//                Left.Add(R16L16[i]);
//            }
//            int lvl = 0;
//            while (lvl < 16)
//            {
//                List<char> XORED = new List<char>();
//                Dictionary<int, char> expandedRight = new Dictionary<int, char>();
//                #region
//                expandedRight[0] = right[31];
//                expandedRight[1] = right[0];
//                expandedRight[2] = right[1];
//                expandedRight[3] = right[2];
//                expandedRight[4] = right[3];
//                expandedRight[5] = right[4];

//                expandedRight[6] = right[3];
//                expandedRight[7] = right[4];
//                expandedRight[8] = right[5];
//                expandedRight[9] = right[6];
//                expandedRight[10] = right[7];
//                expandedRight[11] = right[8];

//                expandedRight[12] = right[7];
//                expandedRight[13] = right[8];
//                expandedRight[14] = right[9];
//                expandedRight[15] = right[10];
//                expandedRight[16] = right[11];
//                expandedRight[17] = right[12];

//                expandedRight[18] = right[11];
//                expandedRight[19] = right[12];
//                expandedRight[20] = right[13];
//                expandedRight[21] = right[14];
//                expandedRight[22] = right[15];
//                expandedRight[23] = right[16];

//                expandedRight[24] = right[15];
//                expandedRight[25] = right[16];
//                expandedRight[26] = right[17];
//                expandedRight[27] = right[18];
//                expandedRight[28] = right[19];
//                expandedRight[29] = right[20];

//                expandedRight[30] = right[19];
//                expandedRight[31] = right[20];
//                expandedRight[32] = right[21];
//                expandedRight[33] = right[22];
//                expandedRight[34] = right[23];
//                expandedRight[35] = right[24];

//                expandedRight[36] = right[23];
//                expandedRight[37] = right[24];
//                expandedRight[38] = right[25];
//                expandedRight[39] = right[26];
//                expandedRight[40] = right[27];
//                expandedRight[41] = right[28];

//                expandedRight[42] = right[27];
//                expandedRight[43] = right[28];
//                expandedRight[44] = right[29];
//                expandedRight[45] = right[30];
//                expandedRight[46] = right[31];
//                expandedRight[47] = right[0];
//                #endregion
//                //foreach (var val in expandedRight.Values) Console.Write(val);
//                for (int i = 0; i < keys[lvl].Count; i++)
//                {
//                    for (int j = 0; j < expandedRight.Count; j++)
//                    {
//                        if (keys[lvl][i] == expandedRight[j])
//                        {
//                            XORED.Add('0');
//                        }
//                        else
//                            XORED.Add('1');
//                    }
//                }
//                List<char> block1 = new List<char>();
//                List<char> block2 = new List<char>();
//                List<char> block3 = new List<char>();
//                List<char> block4 = new List<char>();
//                List<char> block5 = new List<char>();
//                List<char> block6 = new List<char>();
//                List<char> block7 = new List<char>();
//                List<char> block8 = new List<char>();
//                List<char> before_perm = new List<char>();
//                StringBuilder tmp1 = new StringBuilder();
//                StringBuilder tmp2 = new StringBuilder();
//                for (int b = 0; b < 6; b++)
//                { block1.Add(XORED[b]); }
//                for (int b = 6; b < 12; b++)
//                { block2.Add(XORED[b]); }
//                for (int b = 12; b < 18; b++)
//                { block3.Add(XORED[b]); }
//                for (int b = 18; b < 24; b++)
//                { block4.Add(XORED[b]); }
//                for (int b = 24; b < 30; b++)
//                { block5.Add(XORED[b]); }
//                for (int b = 30; b < 36; b++)
//                { block6.Add(XORED[b]); }
//                for (int b = 36; b < 42; b++)
//                { block7.Add(XORED[b]); }
//                for (int b = 42; b < 48; b++)
//                { block8.Add(XORED[b]); }
//                List<int> s_boxR = new List<int>();
//                int x = 0, y = 0;
//                //b1
//                tmp1.Append(block1[0]);
//                tmp1.Append(block1[5]);
//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }
//                tmp2.Append(block1[1]);
//                tmp2.Append(block1[2]);
//                tmp2.Append(block1[3]);
//                tmp2.Append(block1[4]);
//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s1[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b2
//                tmp1.Append(block2[0]);
//                tmp1.Append(block2[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block2[1]);
//                tmp2.Append(block2[2]);
//                tmp2.Append(block2[3]);
//                tmp2.Append(block2[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s2[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b3
//                tmp1.Append(block3[0]);
//                tmp1.Append(block3[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block3[1]);
//                tmp2.Append(block3[2]);
//                tmp2.Append(block3[3]);
//                tmp2.Append(block3[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s3[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b4
//                tmp1.Append(block4[0]);
//                tmp1.Append(block4[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block4[1]);
//                tmp2.Append(block4[2]);
//                tmp2.Append(block4[3]);
//                tmp2.Append(block4[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s4[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b5
//                tmp1.Append(block5[0]);
//                tmp1.Append(block5[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block5[1]);
//                tmp2.Append(block5[2]);
//                tmp2.Append(block5[3]);
//                tmp2.Append(block5[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s5[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b6
//                tmp1.Append(block6[0]);
//                tmp1.Append(block6[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block6[1]);
//                tmp2.Append(block6[2]);
//                tmp2.Append(block6[3]);
//                tmp2.Append(block6[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s6[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b7
//                tmp1.Append(block7[0]);
//                tmp1.Append(block7[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block7[1]);
//                tmp2.Append(block7[2]);
//                tmp2.Append(block7[3]);
//                tmp2.Append(block7[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s7[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;

//                tmp1.Append(block8[0]);
//                tmp1.Append(block8[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block8[1]);
//                tmp2.Append(block8[2]);
//                tmp2.Append(block8[3]);
//                tmp2.Append(block8[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s8[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                for (int h = 0; h < s_boxR.Count; h++)
//                {
//                    int number = s_boxR[h];
//                    string Result = string.Empty;

//                    while (number > 0)
//                    {
//                        Result = number % 2 + Result;
//                        number = number / 2;
//                    }
//                    string zeros = "";
//                    for (int kk = 0; kk < 4 - Result.Length; kk++) zeros = zeros.Insert(zeros.Length, "0");
//                    Result = zeros + Result;
//                    for (int z = 0; z < Result.Length; z++) { before_perm.Add(Result[z]); }


//                }
//                SortedDictionary<int, char> perm_table = new SortedDictionary<int, char>();
//                perm_table[0] = before_perm[15];
//                perm_table[1] = before_perm[6];
//                perm_table[2] = before_perm[19];
//                perm_table[3] = before_perm[20];
//                perm_table[4] = before_perm[28];
//                perm_table[5] = before_perm[11];
//                perm_table[6] = before_perm[27];
//                perm_table[7] = before_perm[16];
//                perm_table[8] = before_perm[0];
//                perm_table[9] = before_perm[14];
//                perm_table[10] = before_perm[22];
//                perm_table[11] = before_perm[25];
//                perm_table[12] = before_perm[4];
//                perm_table[13] = before_perm[17];
//                perm_table[14] = before_perm[30];
//                perm_table[15] = before_perm[9];
//                perm_table[16] = before_perm[1];
//                perm_table[17] = before_perm[7];
//                perm_table[18] = before_perm[23];
//                perm_table[19] = before_perm[13];
//                perm_table[20] = before_perm[31];
//                perm_table[21] = before_perm[26];
//                perm_table[22] = before_perm[2];
//                perm_table[23] = before_perm[8];
//                perm_table[24] = before_perm[18];
//                perm_table[25] = before_perm[12];
//                perm_table[26] = before_perm[29];
//                perm_table[27] = before_perm[5];
//                perm_table[28] = before_perm[21];
//                perm_table[29] = before_perm[10];
//                perm_table[30] = before_perm[3];
//                perm_table[31] = before_perm[24];
//                List<char> after_perm = new List<char>();
//                for (int v = 0; v < before_perm.Count; v++)
//                {
//                    after_perm.Add(perm_table[v]);
//                }
//                List<char> newLeft = new List<char>();
//                for (int i = 0; i < right.Count; i++)
//                {
//                    newLeft.Add(right[i]);
//                }
//                right = new List<char>();
//                for (int a = 0; a < 32; a++)
//                {
//                    if (after_perm[a] == Left[a]) { right.Add('0'); }
//                    else { right.Add('1'); }
//                }
//                Left = newLeft;
//                lvl++;

//            }
//            string PT = "";
//            foreach (var val in Left)
//            {
//                PT = PT.Insert(PT.Length, val.ToString());
//            }
//            foreach (var val in right)
//            {
//                PT = PT.Insert(PT.Length, val.ToString());
//            }
//            string strHex = Convert.ToInt64(PT, 2).ToString("X");
//            return strHex;
//        }

//        public override string Encrypt(string plainText, string key)
//        {
//            //string mainCipher = "0x85E813540F0AB405";
//            // string mainPlain = "0x0123456789ABCDEF";
//           // string plainText = "0x0123456789ABCDEF";
//            //string key = "0x133457799BBCDFF1";
//            string binaryMainCipher = Convert.ToString(Convert.ToInt64(plainText, 16), 2);
//            string tempCipher = "";

//            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
//            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
//            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
//            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
//            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
//            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
//            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
//            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };



//            for (int i = 0; i < 64 - binaryMainCipher.Length; i++)
//            {
//                tempCipher = tempCipher.Insert(tempCipher.Length, "0");
//            }
//            binaryMainCipher = tempCipher + binaryMainCipher;
//            string binaryMainKey = Convert.ToString(Convert.ToInt64(key, 16), 2);
//            string tempKey = "";
//            for (int i = 0; i < 64 - binaryMainKey.Length; i++)
//            {
//                tempKey = tempKey.Insert(tempKey.Length, "0");
//            }
//            binaryMainKey = tempKey + binaryMainKey;
//            Dictionary<int, char> PC_1Map = new Dictionary<int, char>();
//            {
//                PC_1Map[1] = binaryMainKey[56];
//                PC_1Map[2] = binaryMainKey[48];
//                PC_1Map[3] = binaryMainKey[40];
//                PC_1Map[4] = binaryMainKey[32];
//                PC_1Map[5] = binaryMainKey[24];
//                PC_1Map[6] = binaryMainKey[16];
//                PC_1Map[7] = binaryMainKey[8];
//                PC_1Map[8] = binaryMainKey[0];
//                PC_1Map[9] = binaryMainKey[57];
//                PC_1Map[10] = binaryMainKey[49];
//                PC_1Map[11] = binaryMainKey[41];
//                PC_1Map[12] = binaryMainKey[33];
//                PC_1Map[13] = binaryMainKey[25];
//                PC_1Map[14] = binaryMainKey[17];
//                PC_1Map[15] = binaryMainKey[9];
//                PC_1Map[16] = binaryMainKey[1];
//                PC_1Map[17] = binaryMainKey[58];
//                PC_1Map[18] = binaryMainKey[50];
//                PC_1Map[19] = binaryMainKey[42];
//                PC_1Map[20] = binaryMainKey[34];
//                PC_1Map[21] = binaryMainKey[26];
//                PC_1Map[22] = binaryMainKey[18];
//                PC_1Map[23] = binaryMainKey[10];
//                PC_1Map[24] = binaryMainKey[2];
//                PC_1Map[25] = binaryMainKey[59];
//                PC_1Map[26] = binaryMainKey[51];
//                PC_1Map[27] = binaryMainKey[43];
//                PC_1Map[28] = binaryMainKey[35];
//                PC_1Map[29] = binaryMainKey[62];
//                PC_1Map[30] = binaryMainKey[54];
//                PC_1Map[31] = binaryMainKey[46];
//                PC_1Map[32] = binaryMainKey[38];
//                PC_1Map[33] = binaryMainKey[30];
//                PC_1Map[34] = binaryMainKey[22];
//                PC_1Map[35] = binaryMainKey[14];
//                PC_1Map[36] = binaryMainKey[6];
//                PC_1Map[37] = binaryMainKey[61];
//                PC_1Map[38] = binaryMainKey[55];
//                PC_1Map[39] = binaryMainKey[45];
//                PC_1Map[40] = binaryMainKey[37];
//                PC_1Map[41] = binaryMainKey[29];
//                PC_1Map[42] = binaryMainKey[21];
//                PC_1Map[43] = binaryMainKey[13];
//                PC_1Map[44] = binaryMainKey[5];
//                PC_1Map[45] = binaryMainKey[60];
//                PC_1Map[46] = binaryMainKey[52];
//                PC_1Map[47] = binaryMainKey[44];
//                PC_1Map[48] = binaryMainKey[36];
//                PC_1Map[49] = binaryMainKey[28];
//                PC_1Map[50] = binaryMainKey[20];
//                PC_1Map[51] = binaryMainKey[12];
//                PC_1Map[52] = binaryMainKey[4];
//                PC_1Map[53] = binaryMainKey[27];
//                PC_1Map[54] = binaryMainKey[19];
//                PC_1Map[55] = binaryMainKey[11];
//                PC_1Map[56] = binaryMainKey[3];
//            }
//            List<char> C0 = new List<char>();
//            List<char> D0 = new List<char>();
//            for (int i = 1; i <= 28; i++)
//            {
//                C0.Add(PC_1Map[i]);
//            }
//            for (int i = 29; i <= 56; i++)
//            {
//                D0.Add(PC_1Map[i]);
//            }
//            List<char> tempc = new List<char>();
//            List<char> tempd = new List<char>();
//            for (int i = 0; i < 28; i++)
//            {
//                tempc.Add(C0[i]);
//            }

//            for (int i = 0; i < 28; i++)
//            {
//                tempd.Add(D0[i]);
//            }
//            List<List<char>> keys = new List<List<char>>();
//            Dictionary<int, char> k1_map = new Dictionary<int, char>();
//            char temp1 = tempc[0];
//            for (int i = 0; i < 28; i++)
//            {
//                if (i == 27)
//                {
//                    tempc[i] = temp1;
//                }
//                else
//                {
//                    tempc[i] = tempc[i + 1];
//                }
//            }
//            char temp2 = tempd[0];
//            for (int i = 0; i < 28; i++)
//            {

//                if (i == 27)
//                {
//                    tempd[i] = temp2;
//                }
//                else
//                {
//                    tempd[i] = tempd[i + 1];
//                }
//            }
//            k1_map.Clear();
//            List<char> temp = new List<char>();
//            for (int i = 0; i < tempc.Count; i++) temp.Add(tempc[i]);
//            temp.AddRange(tempd);
//            {
//                k1_map[1] = temp[13];
//                k1_map[2] = temp[13];
//                k1_map[3] = temp[10];
//                k1_map[4] = temp[23];
//                k1_map[5] = temp[0];
//                k1_map[6] = temp[4];
//                k1_map[7] = temp[2];
//                k1_map[8] = temp[27];
//                k1_map[9] = temp[14];
//                k1_map[10] = temp[5];
//                k1_map[11] = temp[20];
//                k1_map[12] = temp[9];
//                k1_map[13] = temp[22];
//                k1_map[14] = temp[18];
//                k1_map[15] = temp[11];
//                k1_map[16] = temp[3];
//                k1_map[17] = temp[25];
//                k1_map[18] = temp[7];
//                k1_map[19] = temp[15];
//                k1_map[20] = temp[6];
//                k1_map[21] = temp[26];
//                k1_map[22] = temp[19];
//                k1_map[23] = temp[12];
//                k1_map[24] = temp[1];
//                k1_map[25] = temp[40];
//                k1_map[26] = temp[51];
//                k1_map[27] = temp[30];
//                k1_map[28] = temp[36];
//                k1_map[29] = temp[46];
//                k1_map[30] = temp[54];
//                k1_map[31] = temp[29];
//                k1_map[32] = temp[39];
//                k1_map[33] = temp[50];
//                k1_map[34] = temp[44];
//                k1_map[35] = temp[32];
//                k1_map[36] = temp[47];
//                k1_map[37] = temp[43];
//                k1_map[38] = temp[48];
//                k1_map[39] = temp[38];
//                k1_map[40] = temp[55];
//                k1_map[41] = temp[33];
//                k1_map[42] = temp[52];
//                k1_map[43] = temp[45];
//                k1_map[44] = temp[41];
//                k1_map[45] = temp[49];
//                k1_map[46] = temp[35];
//                k1_map[47] = temp[28];
//                k1_map[48] = temp[31];
//            }
//            List<char> k = new List<char>();
//            foreach (var val in k1_map.Values) k.Add(val);
//            keys.Add(k);

//            int iter = 1;
//            while (iter < 16)
//            {
//                temp1 = tempc[0];
//                for (int i = 0; i < 28; i++)
//                {
//                    if (i == 27)
//                    {
//                        tempc[i] = temp1;
//                    }
//                    else
//                    {
//                        tempc[i] = tempc[i + 1];
//                    }
//                }
//                temp2 = tempd[0];
//                for (int i = 0; i < 28; i++)
//                {

//                    if (i == 27)
//                    {
//                        tempd[i] = temp2;
//                    }
//                    else
//                    {
//                        tempd[i] = tempd[i + 1];
//                    }
//                }
//                if (iter == 2 || iter == 3 || iter == 4 || iter == 5 || iter == 6 || iter == 7
//                    || iter == 9 || iter == 10 || iter == 11 || iter == 12 || iter == 13 || iter == 14)
//                {
//                    temp1 = tempc[0];
//                    for (int i = 0; i < 28; i++)
//                    {
//                        if (i == 27)
//                        {
//                            tempc[i] = temp1;
//                        }
//                        else
//                        {
//                            tempc[i] = tempc[i + 1];
//                        }
//                    }
//                    temp2 = tempd[0];
//                    for (int i = 0; i < 28; i++)
//                    {

//                        if (i == 27)
//                        {
//                            tempd[i] = temp2;
//                        }
//                        else
//                        {
//                            tempd[i] = tempd[i + 1];
//                        }
//                    }
//                }
//                temp = new List<char>();
//                for (int i = 0; i < tempc.Count; i++) temp.Add(tempc[i]);
//                temp.AddRange(tempd);
//                {
//                    k1_map[1] = temp[13];
//                    k1_map[2] = temp[16];
//                    k1_map[3] = temp[10];
//                    k1_map[4] = temp[23];
//                    k1_map[5] = temp[0];
//                    k1_map[6] = temp[4];
//                    k1_map[7] = temp[2];
//                    k1_map[8] = temp[27];
//                    k1_map[9] = temp[14];
//                    k1_map[10] = temp[5];
//                    k1_map[11] = temp[20];
//                    k1_map[12] = temp[9];
//                    k1_map[13] = temp[22];
//                    k1_map[14] = temp[18];
//                    k1_map[15] = temp[11];
//                    k1_map[16] = temp[3];
//                    k1_map[17] = temp[25];
//                    k1_map[18] = temp[7];
//                    k1_map[19] = temp[15];
//                    k1_map[20] = temp[6];
//                    k1_map[21] = temp[26];
//                    k1_map[22] = temp[19];
//                    k1_map[23] = temp[12];
//                    k1_map[24] = temp[1];
//                    k1_map[25] = temp[40];
//                    k1_map[26] = temp[51];
//                    k1_map[27] = temp[30];
//                    k1_map[28] = temp[36];
//                    k1_map[29] = temp[46];
//                    k1_map[30] = temp[54];
//                    k1_map[31] = temp[29];
//                    k1_map[32] = temp[39];
//                    k1_map[33] = temp[50];
//                    k1_map[34] = temp[44];
//                    k1_map[35] = temp[32];
//                    k1_map[36] = temp[47];
//                    k1_map[37] = temp[43];
//                    k1_map[38] = temp[48];
//                    k1_map[39] = temp[38];
//                    k1_map[40] = temp[55];
//                    k1_map[41] = temp[33];
//                    k1_map[42] = temp[52];
//                    k1_map[43] = temp[45];
//                    k1_map[44] = temp[41];
//                    k1_map[45] = temp[49];
//                    k1_map[46] = temp[35];
//                    k1_map[47] = temp[28];
//                    k1_map[48] = temp[31];
//                }
//                k = new List<char>();
//                foreach (var val in k1_map.Values) k.Add(val);
//                keys.Add(k);


//                iter++;

//            }
//            //foreach (var val in keys)
//            //{

//            //    for (int i = 0; i < val.Count; i++)
//            //    {
//            //        Console.Write(val[i]);
//            //    }
//            //    Console.WriteLine();
//            //}



//            //SortedDictionary<int, char> R16L16Map = new SortedDictionary<int, char>();
//            //{
//            //    R16L16Map[40] = binaryMainCipher[0];
//            //    R16L16Map[8] = binaryMainCipher[1];
//            //    R16L16Map[48] = binaryMainCipher[2];
//            //    R16L16Map[16] = binaryMainCipher[3];
//            //    R16L16Map[56] = binaryMainCipher[4];
//            //    R16L16Map[24] = binaryMainCipher[5];
//            //    R16L16Map[64] = binaryMainCipher[6];
//            //    R16L16Map[32] = binaryMainCipher[7];
//            //    R16L16Map[39] = binaryMainCipher[8];
//            //    R16L16Map[7] = binaryMainCipher[9];
//            //    R16L16Map[47] = binaryMainCipher[10];
//            //    R16L16Map[15] = binaryMainCipher[11];
//            //    R16L16Map[55] = binaryMainCipher[12];
//            //    R16L16Map[23] = binaryMainCipher[13];
//            //    R16L16Map[63] = binaryMainCipher[14];
//            //    R16L16Map[31] = binaryMainCipher[15];
//            //    R16L16Map[38] = binaryMainCipher[16];
//            //    R16L16Map[6] = binaryMainCipher[17];
//            //    R16L16Map[46] = binaryMainCipher[18];
//            //    R16L16Map[14] = binaryMainCipher[19];
//            //    R16L16Map[54] = binaryMainCipher[20];
//            //    R16L16Map[22] = binaryMainCipher[21];
//            //    R16L16Map[62] = binaryMainCipher[22];
//            //    R16L16Map[30] = binaryMainCipher[23];
//            //    R16L16Map[37] = binaryMainCipher[24];
//            //    R16L16Map[5] = binaryMainCipher[25];
//            //    R16L16Map[45] = binaryMainCipher[26];
//            //    R16L16Map[13] = binaryMainCipher[27];
//            //    R16L16Map[53] = binaryMainCipher[28];
//            //    R16L16Map[21] = binaryMainCipher[29];
//            //    R16L16Map[61] = binaryMainCipher[30];
//            //    R16L16Map[29] = binaryMainCipher[31];
//            //    R16L16Map[36] = binaryMainCipher[32];
//            //    R16L16Map[4] = binaryMainCipher[33];
//            //    R16L16Map[44] = binaryMainCipher[34];
//            //    R16L16Map[12] = binaryMainCipher[35];
//            //    R16L16Map[52] = binaryMainCipher[36];
//            //    R16L16Map[20] = binaryMainCipher[37];
//            //    R16L16Map[60] = binaryMainCipher[38];
//            //    R16L16Map[28] = binaryMainCipher[39];
//            //    R16L16Map[35] = binaryMainCipher[40];
//            //    R16L16Map[3] = binaryMainCipher[41];
//            //    R16L16Map[43] = binaryMainCipher[42];
//            //    R16L16Map[11] = binaryMainCipher[43];
//            //    R16L16Map[51] = binaryMainCipher[44];
//            //    R16L16Map[19] = binaryMainCipher[45];
//            //    R16L16Map[59] = binaryMainCipher[46];
//            //    R16L16Map[27] = binaryMainCipher[47];
//            //    R16L16Map[34] = binaryMainCipher[48];
//            //    R16L16Map[2] = binaryMainCipher[49];
//            //    R16L16Map[42] = binaryMainCipher[50];
//            //    R16L16Map[10] = binaryMainCipher[51];
//            //    R16L16Map[50] = binaryMainCipher[52];
//            //    R16L16Map[18] = binaryMainCipher[53];
//            //    R16L16Map[58] = binaryMainCipher[54];
//            //    R16L16Map[26] = binaryMainCipher[55];
//            //    R16L16Map[33] = binaryMainCipher[56];
//            //    R16L16Map[1] = binaryMainCipher[57];
//            //    R16L16Map[41] = binaryMainCipher[58];
//            //    R16L16Map[9] = binaryMainCipher[59];
//            //    R16L16Map[49] = binaryMainCipher[60];
//            //    R16L16Map[17] = binaryMainCipher[61];
//            //    R16L16Map[57] = binaryMainCipher[62];
//            //    R16L16Map[25] = binaryMainCipher[63];
//            //}

//            Dictionary<int, char> R16L16Map = new Dictionary<int, char>();
//            {
//                R16L16Map[0] = binaryMainCipher[57];
//                R16L16Map[1] = binaryMainCipher[49];
//                R16L16Map[2] = binaryMainCipher[41];
//                R16L16Map[3] = binaryMainCipher[33];
//                R16L16Map[4] = binaryMainCipher[25];
//                R16L16Map[5] = binaryMainCipher[17];
//                R16L16Map[6] = binaryMainCipher[9];
//                R16L16Map[7] = binaryMainCipher[1];
//                R16L16Map[8] = binaryMainCipher[59];
//                R16L16Map[9] = binaryMainCipher[51];
//                R16L16Map[10] = binaryMainCipher[43];
//                R16L16Map[11] = binaryMainCipher[35];
//                R16L16Map[12] = binaryMainCipher[27];
//                R16L16Map[13] = binaryMainCipher[19];
//                R16L16Map[14] = binaryMainCipher[11];
//                R16L16Map[15] = binaryMainCipher[3];
//                R16L16Map[16] = binaryMainCipher[61];
//                R16L16Map[17] = binaryMainCipher[53];
//                R16L16Map[18] = binaryMainCipher[45];
//                R16L16Map[19] = binaryMainCipher[37];
//                R16L16Map[20] = binaryMainCipher[29];
//                R16L16Map[21] = binaryMainCipher[21];
//                R16L16Map[22] = binaryMainCipher[13];
//                R16L16Map[23] = binaryMainCipher[5];
//                R16L16Map[24] = binaryMainCipher[63];
//                R16L16Map[25] = binaryMainCipher[55];
//                R16L16Map[26] = binaryMainCipher[47];
//                R16L16Map[27] = binaryMainCipher[39];
//                R16L16Map[28] = binaryMainCipher[31];
//                R16L16Map[29] = binaryMainCipher[23];
//                R16L16Map[30] = binaryMainCipher[15];
//                R16L16Map[31] = binaryMainCipher[7];
//                R16L16Map[32] = binaryMainCipher[56];
//                R16L16Map[33] = binaryMainCipher[48];
//                R16L16Map[34] = binaryMainCipher[40];
//                R16L16Map[35] = binaryMainCipher[32];
//                R16L16Map[36] = binaryMainCipher[24];
//                R16L16Map[37] = binaryMainCipher[16];
//                R16L16Map[38] = binaryMainCipher[8];
//                R16L16Map[39] = binaryMainCipher[0];
//                R16L16Map[40] = binaryMainCipher[58];
//                R16L16Map[41] = binaryMainCipher[50];
//                R16L16Map[42] = binaryMainCipher[42];
//                R16L16Map[43] = binaryMainCipher[34];
//                R16L16Map[44] = binaryMainCipher[26];
//                R16L16Map[45] = binaryMainCipher[18];
//                R16L16Map[46] = binaryMainCipher[10];
//                R16L16Map[47] = binaryMainCipher[2];
//                R16L16Map[48] = binaryMainCipher[60];
//                R16L16Map[49] = binaryMainCipher[52];
//                R16L16Map[50] = binaryMainCipher[44];
//                R16L16Map[51] = binaryMainCipher[36];
//                R16L16Map[52] = binaryMainCipher[28];
//                R16L16Map[53] = binaryMainCipher[20];
//                R16L16Map[54] = binaryMainCipher[12];
//                R16L16Map[55] = binaryMainCipher[4];
//                R16L16Map[56] = binaryMainCipher[62];
//                R16L16Map[57] = binaryMainCipher[54];
//                R16L16Map[58] = binaryMainCipher[46];
//                R16L16Map[59] = binaryMainCipher[38];
//                R16L16Map[60] = binaryMainCipher[30];
//                R16L16Map[61] = binaryMainCipher[22];
//                R16L16Map[62] = binaryMainCipher[14];
//                R16L16Map[63] = binaryMainCipher[6];
//            }
//            List<char> R16L16 = new List<char>();
//            foreach (var val in R16L16Map.Values)
//            {
//                R16L16.Add(val);
//            }
//            List<char> Left = new List<char>();
//            List<char> right = new List<char>();
//            for (int i = 0; i < 32; i++)
//            {
//                Left.Add(R16L16[i]);
//            }
//            for (int i = 32; i < 64; i++)
//            {
//                right.Add(R16L16[i]);
//            }
//            int lvl = 0;

//            while (lvl < 16)
//            {
//                List<char> XORED = new List<char>();
//                Dictionary<int, char> expandedRight = new Dictionary<int, char>();
//                #region
//                expandedRight[0] = right[31];
//                expandedRight[1] = right[0];
//                expandedRight[2] = right[1];
//                expandedRight[3] = right[2];
//                expandedRight[4] = right[3];
//                expandedRight[5] = right[4];

//                expandedRight[6] = right[3];
//                expandedRight[7] = right[4];
//                expandedRight[8] = right[5];
//                expandedRight[9] = right[6];
//                expandedRight[10] = right[7];
//                expandedRight[11] = right[8];

//                expandedRight[12] = right[7];
//                expandedRight[13] = right[8];
//                expandedRight[14] = right[9];
//                expandedRight[15] = right[10];
//                expandedRight[16] = right[11];
//                expandedRight[17] = right[12];

//                expandedRight[18] = right[11];
//                expandedRight[19] = right[12];
//                expandedRight[20] = right[13];
//                expandedRight[21] = right[14];
//                expandedRight[22] = right[15];
//                expandedRight[23] = right[16];

//                expandedRight[24] = right[15];
//                expandedRight[25] = right[16];
//                expandedRight[26] = right[17];
//                expandedRight[27] = right[18];
//                expandedRight[28] = right[19];
//                expandedRight[29] = right[20];

//                expandedRight[30] = right[19];
//                expandedRight[31] = right[20];
//                expandedRight[32] = right[21];
//                expandedRight[33] = right[22];
//                expandedRight[34] = right[23];
//                expandedRight[35] = right[24];

//                expandedRight[36] = right[23];
//                expandedRight[37] = right[24];
//                expandedRight[38] = right[25];
//                expandedRight[39] = right[26];
//                expandedRight[40] = right[27];
//                expandedRight[41] = right[28];

//                expandedRight[42] = right[27];
//                expandedRight[43] = right[28];
//                expandedRight[44] = right[29];
//                expandedRight[45] = right[30];
//                expandedRight[46] = right[31];
//                expandedRight[47] = right[0];
//                #endregion


//                int ii = 0;
//                for (int j = 0; j < expandedRight.Count; j++)
//                {
//                    if (keys[lvl][ii] == expandedRight[j])
//                    {
//                        XORED.Add('0');
//                    }
//                    else
//                    {
//                        XORED.Add('1');
//                    }
//                    ii++;
//                }

//                List<char> block1 = new List<char>();
//                List<char> block2 = new List<char>();
//                List<char> block3 = new List<char>();
//                List<char> block4 = new List<char>();
//                List<char> block5 = new List<char>();
//                List<char> block6 = new List<char>();
//                List<char> block7 = new List<char>();
//                List<char> block8 = new List<char>();
//                List<char> before_perm = new List<char>();
//                StringBuilder tmp1 = new StringBuilder();
//                StringBuilder tmp2 = new StringBuilder();
//                for (int b = 0; b < 6; b++)
//                { block1.Add(XORED[b]); }
//                for (int b = 6; b < 12; b++)
//                { block2.Add(XORED[b]); }
//                for (int b = 12; b < 18; b++)
//                { block3.Add(XORED[b]); }
//                for (int b = 18; b < 24; b++)
//                { block4.Add(XORED[b]); }
//                for (int b = 24; b < 30; b++)
//                { block5.Add(XORED[b]); }
//                for (int b = 30; b < 36; b++)
//                { block6.Add(XORED[b]); }
//                for (int b = 36; b < 42; b++)
//                { block7.Add(XORED[b]); }
//                for (int b = 42; b < 48; b++)
//                { block8.Add(XORED[b]); }
//                List<int> s_boxR = new List<int>();
//                int x = 0, y = 0;
//                //b1
//                tmp1.Append(block1[0]);
//                tmp1.Append(block1[5]);
//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }
//                tmp2.Append(block1[1]);
//                tmp2.Append(block1[2]);
//                tmp2.Append(block1[3]);
//                tmp2.Append(block1[4]);
//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s1[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b2
//                tmp1.Append(block2[0]);
//                tmp1.Append(block2[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block2[1]);
//                tmp2.Append(block2[2]);
//                tmp2.Append(block2[3]);
//                tmp2.Append(block2[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s2[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b3
//                tmp1.Append(block3[0]);
//                tmp1.Append(block3[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block3[1]);
//                tmp2.Append(block3[2]);
//                tmp2.Append(block3[3]);
//                tmp2.Append(block3[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s3[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b4
//                tmp1.Append(block4[0]);
//                tmp1.Append(block4[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block4[1]);
//                tmp2.Append(block4[2]);
//                tmp2.Append(block4[3]);
//                tmp2.Append(block4[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s4[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b5
//                tmp1.Append(block5[0]);
//                tmp1.Append(block5[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block5[1]);
//                tmp2.Append(block5[2]);
//                tmp2.Append(block5[3]);
//                tmp2.Append(block5[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s5[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b6
//                tmp1.Append(block6[0]);
//                tmp1.Append(block6[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block6[1]);
//                tmp2.Append(block6[2]);
//                tmp2.Append(block6[3]);
//                tmp2.Append(block6[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s6[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                //b7
//                tmp1.Append(block7[0]);
//                tmp1.Append(block7[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block7[1]);
//                tmp2.Append(block7[2]);
//                tmp2.Append(block7[3]);
//                tmp2.Append(block7[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s7[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;

//                tmp1.Append(block8[0]);
//                tmp1.Append(block8[5]);

//                if (tmp1.Equals("00")) { x = 0; }
//                else if (tmp1.Equals("01")) { x = 1; }
//                else if (tmp1.Equals("10")) { x = 2; }
//                else if (tmp1.Equals("11")) { x = 3; }

//                tmp2.Append(block8[1]);
//                tmp2.Append(block8[2]);
//                tmp2.Append(block8[3]);
//                tmp2.Append(block8[4]);


//                if (tmp2.Equals("0000")) { y = 0; }
//                else if (tmp2.Equals("0001")) { y = 1; }
//                else if (tmp2.Equals("0010")) { y = 2; }
//                else if (tmp2.Equals("0011")) { y = 3; }
//                else if (tmp2.Equals("0100")) { y = 4; }
//                else if (tmp2.Equals("0101")) { y = 5; }
//                else if (tmp2.Equals("0110")) { y = 6; }
//                else if (tmp2.Equals("0111")) { y = 7; }
//                else if (tmp2.Equals("1000")) { y = 8; }
//                else if (tmp2.Equals("1001")) { y = 9; }
//                else if (tmp2.Equals("1010")) { y = 10; }
//                else if (tmp2.Equals("1011")) { y = 11; }
//                else if (tmp2.Equals("1100")) { y = 12; }
//                else if (tmp2.Equals("1101")) { y = 13; }
//                else if (tmp2.Equals("1110")) { y = 14; }
//                else if (tmp2.Equals("1111")) { y = 15; }
//                s_boxR.Add(s8[x, y]);
//                tmp1 = new StringBuilder();
//                tmp2 = new StringBuilder();
//                x = 0;
//                y = 0;
//                for (int h = 0; h < s_boxR.Count; h++)
//                {
//                    int number = s_boxR[h];
//                    string Result = string.Empty;

//                    while (number > 0)
//                    {
//                        Result = number % 2 + Result;
//                        number = number / 2;
//                    }
//                    string zeros = "";
//                    for (int kk = 0; kk < 4 - Result.Length; kk++) zeros = zeros.Insert(zeros.Length, "0");
//                    Result = zeros + Result;
//                    for (int z = 0; z < Result.Length; z++) { before_perm.Add(Result[z]); }


//                }

//                SortedDictionary<int, char> perm_table = new SortedDictionary<int, char>();
//                perm_table[0] = before_perm[15];
//                perm_table[1] = before_perm[6];
//                perm_table[2] = before_perm[19];
//                perm_table[3] = before_perm[20];
//                perm_table[4] = before_perm[28];
//                perm_table[5] = before_perm[11];
//                perm_table[6] = before_perm[27];
//                perm_table[7] = before_perm[16];
//                perm_table[8] = before_perm[0];
//                perm_table[9] = before_perm[14];
//                perm_table[10] = before_perm[22];
//                perm_table[11] = before_perm[25];
//                perm_table[12] = before_perm[4];
//                perm_table[13] = before_perm[17];
//                perm_table[14] = before_perm[30];
//                perm_table[15] = before_perm[9];
//                perm_table[16] = before_perm[1];
//                perm_table[17] = before_perm[7];
//                perm_table[18] = before_perm[23];
//                perm_table[19] = before_perm[13];
//                perm_table[20] = before_perm[31];
//                perm_table[21] = before_perm[26];
//                perm_table[22] = before_perm[2];
//                perm_table[23] = before_perm[8];
//                perm_table[24] = before_perm[18];
//                perm_table[25] = before_perm[12];
//                perm_table[26] = before_perm[29];
//                perm_table[27] = before_perm[5];
//                perm_table[28] = before_perm[21];
//                perm_table[29] = before_perm[10];
//                perm_table[30] = before_perm[3];
//                perm_table[31] = before_perm[24];
//                List<char> after_perm = new List<char>();
//                for (int v = 0; v < before_perm.Count; v++)
//                {
//                    after_perm.Add(perm_table[v]);
//                }
//                List<char> newLeft = new List<char>();
//                for (int i = 0; i < right.Count; i++)
//                {
//                    newLeft.Add(right[i]);
//                }
//                right = new List<char>();
//                for (int a = 0; a < 32; a++)
//                {
//                    if (after_perm[a] == Left[a]) { right.Add('0'); }
//                    else { right.Add('1'); }
//                }

//                Left = newLeft;
//                lvl++;
//            }
//            string PT = "";
//            foreach (var val in right)
//            {
//                PT = PT.Insert(PT.Length, val.ToString());
//            }
//            foreach (var val in Left)
//            {
//                PT = PT.Insert(PT.Length, val.ToString());
//            }
//            Dictionary<int, char> ans = new Dictionary<int, char>();
//            ans[0] = PT[39];
//            ans[1] = PT[7];
//            ans[2] = PT[47];
//            ans[3] = PT[15];
//            ans[4] = PT[63];
//            ans[5] = PT[23];
//            ans[6] = PT[36];
//            ans[7] = PT[31];


//            ans[8] = PT[38];
//            ans[9] = PT[6];
//            ans[10] = PT[46];
//            ans[11] = PT[14];
//            ans[12] = PT[54];
//            ans[13] = PT[22];
//            ans[14] = PT[62];
//            ans[15] = PT[30];


//            ans[16] = PT[37];
//            ans[17] = PT[5];
//            ans[18] = PT[45];
//            ans[19] = PT[13];
//            ans[20] = PT[53];
//            ans[21] = PT[21];
//            ans[22] = PT[61];
//            ans[23] = PT[29];



//            ans[24] = PT[36];
//            ans[25] = PT[4];
//            ans[26] = PT[44];
//            ans[27] = PT[12];
//            ans[28] = PT[52];
//            ans[29] = PT[20];
//            ans[30] = PT[60];
//            ans[31] = PT[28];


//            ans[32] = PT[35];
//            ans[33] = PT[3];
//            ans[34] = PT[43];
//            ans[35] = PT[11];
//            ans[36] = PT[51];
//            ans[37] = PT[19];
//            ans[38] = PT[59];
//            ans[39] = PT[27];


//            ans[40] = PT[34];
//            ans[41] = PT[2];
//            ans[42] = PT[42];
//            ans[43] = PT[10];
//            ans[44] = PT[50];
//            ans[45] = PT[18];
//            ans[46] = PT[58];
//            ans[47] = PT[26];


//            ans[48] = PT[33];
//            ans[49] = PT[1];
//            ans[50] = PT[41];
//            ans[51] = PT[9];
//            ans[52] = PT[49];
//            ans[53] = PT[19];
//            ans[54] = PT[57];
//            ans[55] = PT[25];


//            ans[56] = PT[32];
//            ans[57] = PT[0];
//            ans[58] = PT[40];
//            ans[59] = PT[8];
//            ans[60] = PT[48];
//            ans[61] = PT[16];
//            ans[62] = PT[56];
//            ans[63] = PT[24];
//            string ptans = "";
//            foreach (var val in ans.Values) ptans = ptans.Insert(ptans.Length, val.ToString());

//            string strHex = String.Format("{0:X2}", Convert.ToUInt64(ptans, 2));          
//            return strHex.ToString();

//        }
//    }
//}