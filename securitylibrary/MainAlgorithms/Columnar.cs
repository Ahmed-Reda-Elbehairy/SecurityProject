using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int H = 0, brk = 0;
            int pl = plainText.Length;
            //hmshy 3l  plaintext bnshof awl hrf f lcipher hwa anhy harf fl plain w bygeb m3a kol lfa lharf l b3d lhrf da
            // w loop l had ma lcipher tkhls lw tany harf fl cipher hwa hwa lharf lb3d lharf lawl ,nfs lklam hnshof lb3do lhad m lcipher ykhls khlis



            for (int i = 0; i < pl; i++)

            {
                if (cipherText[0] == plainText[i])

                {
                    int j = i + 1;

                    while (j < cipherText.Length)

                    {
                        if (cipherText[1] == plainText[j])

                        {
                            int k = j + 1;

                            while (k < cipherText.Length)
                            {
                                if (k - j > j - i)
                                // lw lmsafa ben l (k) w (j) akbr mn lmsafa ben j w i m3nah n msh hwa fa hatl3 bs lw nfs lmsafa benhom hnsgl lfar2 3shan nmshy be
                                {
                                    break;
                                }
                                else if (cipherText[2] == plainText[k] && k - j == j - i)

                                {
                                    H = j - i;
                                    brk = 1;
                                    break;
                                }
                                k++;

                            }
                        }
                        j++;
                        if (brk == 1)
                            break;
                    }
                }
                if (brk == 1)
                    break;
            }
            int columns = H;//wslna l 3add l coloumns
            List<int> key = new List<int>(columns);
            int rows = (int)Math.Ceiling(plainText.Length / (float)H);//3add l rows
            char[,] table = new char[rows, columns];
            int ct0 = 0;
            for (int r = 0; r < rows; r++)//bnmla lmatrix b plaintext w lw lsa mkhlsh l plain bnhot lba2y f matrix lw khlst b2a hnmla b X
            {
                for (int c = 0; c < columns; c++)
                {
                    if (ct0 < plainText.Length)
                    {
                        table[r, c] = plainText[ct0];
                        ct0++;
                    }
                    else
                    {
                        table[r, c] = 'x';
                    }
                }
            }
            for (int i = 0; i < columns; i++)
            //bnmshy 3l coloumns lw wslna l akkher ciphertext aw l harf l fl matrix hwa lharf l flcipher
            {

                int pointer = 0;
                int ck = 0;
                int ct = 2;
                for (int j = 0; j < rows; j++)
                {

                    if ((pointer >= cipherText.Length || table[j, i] == cipherText[pointer]))
                    {
                        ck++;//bnzwd l check 3shan n3rf kam hrf sah
                        if (ck >= rows)
                        { key.Add((int)Math.Ceiling(pointer / (float)rows)); break; }
                        //bnzwd lcolumn da
                        pointer++;
                    }
                    else
                    {
                        j = -1;
                        // lw msh sah arg3 abd2 mn lawl 3l rows
                        int ct_inc = ct++;
                        pointer = ct_inc * rows - rows;
                        //brg3 lpointer mn tany ll 7agm ely kan ablo abl ma ykhosh sah
                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int col = key.Count;
            //b3rf 3dd l col mn 3dd lkeys
            int rows = cipherText.Length / col;
            char[,] table = new char[rows, col];
            string plain = "";
            int Coounter = 1, COUNT2 = 0;
            for (int c = 0; c < col; c++)
            {
                if (Coounter == key[c] && Coounter <= key.Count)
                {
                    for (int r = 0; r < rows; r++)
                    {
                        if (COUNT2 <= cipherText.Length)
                        {
                            table[r, c] = cipherText[COUNT2];
                            COUNT2++;
                        }
                    }
                    Coounter++;
                    c = -1;
                }
            }//bmshy 3l rows wl col 3ady
            for (int i = 0; i < rows; i++)
            {

                for (int H = 0; H < col; H++)
                {

                    plain += table[i, H];
                }
            }
            return plain.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int columns = key.Count;

            //ba3rf 3dd l col mn 3dd l keys w 3dd l rows mn t2semt lklma 3l col
            int rows = (int)Math.Ceiling((double)plainText.Length / columns);


            char[,] table = new char[rows, columns];
            //matrix mn row x col
            string cipheerrr = "";
            int Coounter = 0;
            int My_count = key.Count;
            //w alf 3l matrix lw la2et n l counter a2l mn tol l klelma(m3nah l klma lsa mkhlstsh)
            for (int r = 0; r < rows; r++)

            {
                for (int c = 0; c < columns; c++)
                {
                    if (Coounter < plainText.Length)

                    {
                        table[r, c] = plainText[Coounter];
                        //baht f lmatrix hrf mlklma wlw khlst amla b X 
                        Coounter++;
                    }
                    else

                    {
                        table[r, c] = 'x';
                    }
                }
            }
            Dictionary<int, int> mydic = new Dictionary<int, int>();
            for (int i = 0; i < My_count; i++)

            //bmshy 3lkey w akhle 0 based
            {
                mydic[key[i] - 1] = i;

            }
            int H = 0;
            // w amshy 3l rows wl col wbzwd row w na msbt lcoloumn 3shan a2ra lcol ly fy key
            while (H < My_count)

            {
                for (int R = 0; R < rows; R++)

                {
                    cipheerrr += table[R, mydic[H]];

                }
                H++;
            }
            return cipheerrr.ToUpper();
        }
    }
}
