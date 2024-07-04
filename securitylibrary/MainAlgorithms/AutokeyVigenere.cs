using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] tableau = new char[26, 26];
        int createtableau(char l, ref int row, ref int column)
        {
            for (int r = 0; r < 26; r++)
            {
                for (int c = 0; c < 1; c++)
                {
                    if (l == tableau[r, c])
                        row = r;
                    column = c;
                }
            }

            //loop 3la elrow 3shan ageb elplantext
            return row;

        }
        public string Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            //plainText=plainText.ToLower();
            cipherText = cipherText.ToLower();
            int cipherindex = 0;
            int row = 0;
            int column = 0;
            string key = "";
            //throw new NotImplementedException();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);
                }
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                int getrow = createtableau(plainText[i], ref row, ref column);
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[cipherindex] == tableau[getrow, j])
                    {
                        cipherindex++;
                        key += tableau[0, j];
                        //cipherindex++;
                        break;
                    }
                }
            }
            for (int k = 0; k < key.Length; k++)
            {
                if (plainText[0] == key[k] && plainText[1] == key[k + 1] && plainText[2] == key[k + 2])
                {
                    key = key.Remove(k);
                }
            }

            // return key.ToLower();
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // new NotImplementedException();
            //key=key.toupper()
            cipherText = cipherText.ToLower();

            int dif_chars = 0;
            if (key.Length < cipherText.Length)
            {
                dif_chars = cipherText.Count() - key.Count();
            }

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);

                }

            }
            int row = 0;
            int col = 0;
            int getrow;
            int cipherindex = 0;
            string plaintext = "";
            for (int i = 0; i < key.Length; i++)
            {

                //elkey hykon hoa elrow>>key=getcol,w hsearch goa elrow da 3la char elciper
                getrow = createtableau(key[i], ref row, ref col);


                for (int j = 0; j < 26; j++)
                {
                    if (tableau[getrow, j] == cipherText[cipherindex])
                    {
                        cipherindex++;
                        // tableau[getrow][j];
                        plaintext += tableau[0, j];

                        break;
                    }
                }
            }

            for (int i = 0; i < dif_chars; i++)
            {
                getrow = createtableau(plaintext[i], ref row, ref col);


                for (int j = 0; j < 26; j++)
                {
                    if (tableau[j, getrow] == cipherText[cipherindex])
                    {
                        cipherindex++;

                        plaintext += tableau[0, j];

                        break;
                    }
                }
            }

            // Console.WriteLine(plaintext);
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            while (key.Length < plainText.Length)
            {
                int dif_chars = (plainText.Count() - key.Count());
                for (int i = 0; i < dif_chars; i++)
                {
                    key = key + plainText[i];
                }
            }
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    tableau[i, j] = (char)(((i + j) % 26) + 97);
                }
            }

            int keyindex = 0;
            int column = 0;
            int row = 0;
            string cipher_text = "";

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
