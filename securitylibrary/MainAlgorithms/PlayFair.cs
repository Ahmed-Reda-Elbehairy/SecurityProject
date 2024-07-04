using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            
            /* 
             we will use the same matrix as in the encryption
             but the strps will be reversed
             
             
             */          
            bool flag = false;
            List<char> vec = new List<char>();


            key = key.ToLower();

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'i' || key[i] == 'j')
                    flag = true;


                if (vec.Contains(key[i]))
                {
                    continue;
                }
                else
                {

                    vec.Add(key[i]);

                }
            }
            List<char> vec2 = new List<char>();
            if (flag)
            {
                for (int i = 0; i < vec.Count; i++)
                {
                    if (vec[i] == 'i' || vec[i] == 'j')
                    {
                        if (vec2.Contains('i') || vec2.Contains('j'))
                        {
                            continue;
                        }
                        else
                        {
                            vec2.Add(vec[i]);
                        }
                    }
                    else
                    {

                        vec2.Add(vec[i]);
                    }


                }
            }
            else
            {
                for (int i = 0; i < vec.Count; i++)
                {
                    vec2.Add(vec[i]);

                }

            }

            List<char> chars = new List<char>();
            chars.Add('a');
            chars.Add('b');
            chars.Add('c');
            chars.Add('d');
            chars.Add('e');
            chars.Add('f');
            chars.Add('g');
            chars.Add('h');
            chars.Add('i');
            chars.Add('k');
            chars.Add('l');
            chars.Add('m');
            chars.Add('n');
            chars.Add('o');
            chars.Add('p');
            chars.Add('q');
            chars.Add('r');
            chars.Add('s');
            chars.Add('t');
            chars.Add('u');
            chars.Add('v');
            chars.Add('w');
            chars.Add('x');
            chars.Add('y');
            chars.Add('z');

            char[,] matrix = { { 'z', 'j', 'j', 'i', 'j' }, { 'v', 'j', 'j', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' } };
            List<char> matrixx = new List<char>();
            int counter = 0;
            int counter2 = 0;
            for (int i = 0; i < 5; i++)
            {

                for (int j = 0; j < 5; j++)
                {
                    counter2++;
                    if (counter <= (vec2.Count) - 1)
                    {
                        matrix[i, j] = vec2[counter];
                        matrixx.Add(vec2[counter]);
                        counter++;
                    }
                    else
                    {
                        for (int c = 0; c < 25; c++)
                        {
                            if (matrixx.Contains(chars[c]) == true)
                                continue;
                            else
                            {
                                if (chars[c] == 'i' || chars[c] == 'j')
                                {
                                    if (matrixx.Contains('i') || matrixx.Contains('j'))
                                        continue;
                                }
                                matrix[i, j] = chars[c];
                                matrixx.Add(chars[c]);
                                break;
                            }

                        }

                    }

                }



            }
            /* for (int i = 0; i < 5; i++)
             {
                 for (int j = 0; j < 5; j++)
                 {
                     Console.WriteLine(matrix[i, j]);
                 }
             }*/






            cipherText = cipherText.ToLower();
            List<char> plain = new List<char>();
            for (int i = 0; i < cipherText.Length; i++)
            {

                plain.Add(cipherText[i]);
            }









            /*  for(int i = 0; i < plain.Count; i++)
              {
                  Console.WriteLine(plain[i]);

              }*/
            List<char> final = new List<char>();

            List<int> result = new List<int>();

            int i1 = 0;
            int i2 = 0;
            int j1 = 0;
            int j2 = 0;
            int id1 = 0;
            int id2 = 0;
            int jd1 = 0;
            int jd2 = 0;
            for (int k = 0; k < plain.Count; k += 2)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (plain[k] == matrix[i, j])
                        {
                            i1 = i;
                            j1 = j;
                        }
                        else if (plain[k + 1] == matrix[i, j])
                        {
                            i2 = i;
                            j2 = j;
                        }
                    }

                }
                if (i1 == i2)
                {
                    id1 = i1;
                    jd1 = (j1 - 1 + 5) % 5;
                    id2 = i2;
                    jd2 = (j2 - 1 + 5) % 5;
                }
                else if (j1 == j2)
                {
                    id1 = (i1 - 1 + 5) % 5;
                    jd1 = j1;
                    id2 = (i2 - 1 + 5) % 5;
                    jd2 = j2;
                }
                else
                {
                    id1 = i1;
                    jd1 = j2;
                    id2 = i2;
                    jd2 = j1;
                }
                final.Add(matrix[id1, jd1]);
                final.Add(matrix[id2, jd2]);

            }




            var v = string.Join("", final.ToArray());
            string decrypted = "";
            for (int i = 0; i < v.Length - 1; i += 2)
            {
                decrypted += v[i];
                if (v[i + 1] != 'x')
                    decrypted += v[i + 1];
                else if (i + 2 < v.Length && v[i + 1] == 'x' && v[i] != v[i + 2])
                    decrypted += v[i + 1];
            }
            decrypted = decrypted.ToUpper();
            return decrypted;





        }

        public string Encrypt(string plainText, string key)
        {
            /*
             the logic of this function will be as follows:
            making a unique matrix containing every singla char in the key then followed bu the normal alphabetic order
            then we will make a map like this "dictionary<char , tuple<int ,int>>" it will contain evey char with its row , column indices
            then we take each two chars in the pt and we search about the intersection (the row of the 1st char and the column of the 2nd char) and vice versa
             if the chars are at the same column or row we than add 1 to each index
             */


            bool flag = false;
            List<char> vec = new List<char>();


            key = key.ToLower();

            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == 'i' || key[i] == 'j')
                    flag = true;


                if (vec.Contains(key[i]))
                {
                    continue;
                }
                else
                {

                    vec.Add(key[i]);

                }
            }
            List<char> vec2 = new List<char>();
            if (flag)
            {
                for (int i = 0; i < vec.Count; i++)
                {
                    if (vec[i] == 'i' || vec[i] == 'j')
                    {
                        if (vec2.Contains('i') || vec2.Contains('j'))
                        {
                            continue;
                        }
                        else
                        {
                            vec2.Add(vec[i]);
                        }
                    }
                    else
                    {

                        vec2.Add(vec[i]);
                    }


                }
            }
            else
            {
                for (int i = 0; i < vec.Count; i++)
                {
                    vec2.Add(vec[i]);

                }

            }

            List<char> chars = new List<char>();
            chars.Add('a');
            chars.Add('b');
            chars.Add('c');
            chars.Add('d');
            chars.Add('e');
            chars.Add('f');
            chars.Add('g');
            chars.Add('h');
            chars.Add('i');
            chars.Add('k');
            chars.Add('l');
            chars.Add('m');
            chars.Add('n');
            chars.Add('o');
            chars.Add('p');
            chars.Add('q');
            chars.Add('r');
            chars.Add('s');
            chars.Add('t');
            chars.Add('u');
            chars.Add('v');
            chars.Add('w');
            chars.Add('x');
            chars.Add('y');
            chars.Add('z');

            char[,] matrix = { { 'z', 'j', 'j', 'i', 'j' }, { 'v', 'j', 'j', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' }, { 'j', 'j', 'u', 'j', 'j' } };
            List<char> matrixx = new List<char>();
            int counter = 0;
            int counter2 = 0;
            for (int i = 0; i < 5; i++)
            {

                for (int j = 0; j < 5; j++)
                {
                    counter2++;
                    if (counter <= (vec2.Count) - 1)
                    {
                        matrix[i, j] = vec2[counter];
                        matrixx.Add(vec2[counter]);
                        counter++;
                    }
                    else
                    {
                        for (int c = 0; c < 25; c++)
                        {
                            if (matrixx.Contains(chars[c]) == true)
                                continue;
                            else
                            {
                                if (chars[c] == 'i' || chars[c] == 'j')
                                {
                                    if (matrixx.Contains('i') || matrixx.Contains('j'))
                                        continue;
                                }
                                matrix[i, j] = chars[c];
                                matrixx.Add(chars[c]);
                                break;
                            }

                        }

                    }

                }



            }






            plainText = plainText.ToLower();
            List<char> plain = new List<char>();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (i != 0)
                {
                    if (plainText[i] == plainText[i - 1] && plain.Count % 2 == 1)
                    {

                        plain.Add('x');
                        plain.Add(plainText[i]);
                    }
                    else
                    {
                        plain.Add(plainText[i]);

                    }
                }
                else
                    plain.Add(plainText[i]);
            }





            if ((plain.Count) % 2 == 1)
            {
                plain.Add('x');

            }

            
           
            
            List<char> final = new List<char>();

            List<int> result = new List<int>();

            int cont = 0;
            for (int k = 0; k < plain.Count; k++)
            {
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (plain[k] == matrix[i, j])
                        {
                            result.Add(i);
                            result.Add(j);
                            cont++;
                        }
                        if (cont % 2 == 0 && cont != 0 && result.Count != 0)
                        {
                            if (result[0] == result[2])
                            {

                                if (result[1] == 4)
                                    final.Add(matrix[result[0], 0]);
                                else
                                    final.Add(matrix[result[0], result[1] + 1]);


                                if (result[3] == 4)
                                    final.Add(matrix[result[0], 0]);
                                else
                                    final.Add(matrix[result[0], result[3] + 1]);

                            }
                            else if (result[1] == result[3])
                            {
                                if (result[0] == 4)
                                    final.Add(matrix[0, result[1]]);
                                else
                                    final.Add(matrix[result[0] + 1, result[1]]);

                                if (result[2] == 4)
                                    final.Add(matrix[0, result[1]]);
                                else
                                    final.Add(matrix[result[2] + 1, result[3]]);

                            }
                            else
                            {
                                final.Add(matrix[result[0], result[3]]);
                                final.Add(matrix[result[2], result[1]]);


                            }


                            result.Clear();


                        }


                    }

                }
            }


            var v = string.Join("", final.ToArray());
            v = v.ToUpper();
            return v;




        }
    }
}