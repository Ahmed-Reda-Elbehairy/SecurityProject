using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        //IChangeTracking[,] table = new char[26, 26];

        char[,] tableau = new char[26, 26];
        int createtableau(char l, ref int row, ref int column)
        {
            for (int r = 0; r < 1; ++r)
                for (int c = 0; c < 26; ++c)
                    if (l == tableau[r, c])
                    {
                        row = r; column = c;
                    }
            return column;
        }


        //loop 3la elrow 3shan ageb elplantext





        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);

                }
            }
            int row = 0, col = 0;
            string key = "";
            int cipherindex = 0;

            //search in plaintext in column 
            //search for cipher in column of palin
            //j of intersection=key
            for (int i = 0; i < plainText.Length; i++)
            {
                //return column of plaintext
                int getrow = createtableau(plainText[i], ref row, ref col);
                for (int j = 0; j < 26; j++)
                {
                    if (tableau[j, getrow] == cipherText[cipherindex])
                    {
                        cipherindex++;
                        // cout << arr[j][v];
                        key += tableau[0, j];

                        break;
                    }
                }

            }
            // return key.ToLower();
            //if key is same characters(kkkkkkk)
            for (int i = 1; i < key.Length; i++)
            {
                if (key[i] == key[0] && key[i + 1] == key[0])
                {
                    key = key.Remove(i);
                }

            }

            for (int i = 2; i < key.Length; i++)
            {
                if (key[0] == key[i] && key[1] == key[i + 1])
                {
                    key = key.Remove(i);

                }
            }
            // Console.WriteLine(key);
            return key;

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            //throw new NotImplementedException();
            if (key.Length < cipherText.Length)
            {
                int dif_chars = cipherText.Count() - key.Count();
                for (int i = 0; i < dif_chars; i++)
                {
                    key = key + key[i];
                }

                // return key_stream;
            }

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);

                }
            }


            int column = 0;
            int row = 0;
            string plain_text = "";
            int keyindex = 0;
            for (int i = 0; i < key.Length; i++)
            {
                //elkey hykon hoa elrow>>key=getcol,w hsearch goa elrow da 3la char elciper
                int getcol = createtableau(key[i], ref row, ref column);
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[keyindex] == tableau[getcol, j])
                    {
                        //cipherText[kayindex]
                        keyindex++;

                        plain_text += tableau[0, j];

                        break;
                    }
                }

            }

            return plain_text;

            //throw new NotImplementedException();
        }


        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            while (key.Length < plainText.Length)
            {
                int dif_chars = (plainText.Count() - key.Count());
                for (int i = 0; i < dif_chars; i++)
                {
                    key = key + key[i];
                }

            }
            //keyindex = index of characters in keystream
            int keyindex = 0;
            int row = 0;
            int column = 0;
            string cipher_text = "";
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int getcol = createtableau(plainText[i], ref row, ref column);
                for (int j = 0; j < 26; j++)
                {
                    if (key[keyindex] == tableau[0, j])
                    {
                        cipher_text += tableau[getcol, j];
                        keyindex++;
                        break;
                    }
                }
            }
            return cipher_text;
        }
    }
}







//throw new NotImplementedException();



//    //   throw new NotImplementedException();
//    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
//    {
//        //IChangeTracking[,] table = new char[26, 26];

//        char[,] tableau = new char[26, 26];
//        int createtableau(char l, ref int row, ref int column)
//        {
//            for (int ro = 0; ro < 26; ro++)
//            {
//                for (int col = 0; col < 1; col++)
//                {
//                    if (l == tableau[ro, col])
//                    {
//                        column = col;
//                        row = ro;
//                    }

//                }
//            }

//            //loop 3la elrow 3shan ageb elplantext
//            return row;

//        }
//        public string Analyse(string plainText, string cipherText)
//        {
//            cipherText = cipherText.ToLower();
//            for (int i = 0; i < 26; i++)
//            {
//                for (int j = 0; j < 26; j++)
//                {
//                    tableau[i, j] = (char)(((i + j) % 26) + 97);

//                }
//            }
//            int row = 0, col = 0;
//            string key = "";
//            int cipherindex = 0;

//            //search in plaintext in column 
//            //search for cipher in column of palin
//            //j of intersection=key
//            for (int i = 0; i < plainText.Length; i++)
//            {
//                //return column of plaintext
//                int getrow = createtableau(plainText[i], ref row, ref col);
//                for (int j = 0; j < 26; j++)
//                {
//                    if (tableau[j, getrow] == cipherText[cipherindex])
//                    {
//                        cipherindex++;
//                        // cout << arr[j][v];
//                        key += tableau[0, j];

//                        break;
//                    }
//                }

//            }
//            // return key.ToLower();
//            //if key is same characters(kkkkkkk)
//            for (int i = 1; i < key.Length; i++)
//            {
//                if (key[i] == key[0] && key[i + 1] == key[0])
//                {
//                    key = key.Remove(i);
//                }

//            }

//            for (int i = 2; i < key.Length; i++)
//            {
//                if (key[0] == key[i] && key[1] == key[i + 1])
//                {
//                    key = key.Remove(i);

//                }
//            }
//            // Console.WriteLine(key);
//            return key;

//        }

//        public string Decrypt(string cipherText, string key)
//        {
//            //string mainPlain = "wearediscoveredsaveyourself";

//            // string mainCipherAuto = "zicvtwqngkzeiigasxstslvvwla".ToUpper();
//            string plainText = "";

//            string keyStream = key;
//            for (int i = 0; i < cipherText.Length - key.Length; i++)
//            {
//                keyStream = keyStream.Insert(keyStream.Length, key[i % key.Length].ToString());
//            }

//            char[,] table = new char[26, 26];
//            for (int i = 0; i < 26; i++)
//            {

//                for (int j = 0; j < 26; j++)
//                {

//                    table[i, j] = (char)(((i + j) % 26) + 97);


//                }

//            }


//            cipherText = cipherText.ToLower();
//            for (int i = 0; i < cipherText.Length; i++)
//            {
//                int row = keyStream[i] - 'a';
//                int character = 0;
//                for (int j = 0; j < 26; j++)
//                {
//                    if (cipherText[i] == table[row, j])
//                    {
//                        character = j;
//                        break;
//                    }
//                }

//                plainText = plainText.Insert(plainText.Length, ((char)(character + 97)).ToString());
//            }
//            return plainText;

//        }

//        public string Encrypt(string plainText, string key)
//        {

//            //string mainCipherRep = "zicvtwqngrzgvtwavzhcqyglmgj".ToUpper();
//            // string mainCipherAuto = "zicvtwqngkzeiigasxstslvvwla".ToUpper();
//            string cipherText = "";

//            string keyStream = key;
//            for (int i = 0; i < plainText.Length - key.Length; i++)
//            {
//                keyStream = keyStream.Insert(keyStream.Length, key[i % key.Length].ToString());
//            }
//            char[,] table = new char[26, 26];
//            for (int i = 0; i < 26; i++)
//            {

//                for (int j = 0; j < 26; j++)
//                {

//                    table[i, j] = (char)(((i + j) % 26) + 97);


//                }

//            }

//            for (int i = 0; i < plainText.Length; i++)
//            {
//                int row = plainText[i] - 'a';
//                int column = keyStream[i] - 'a';
//                cipherText = cipherText.Insert(cipherText.Length, table[row, column].ToString());
//            }
//            return cipherText;
//        }
//    }
//}