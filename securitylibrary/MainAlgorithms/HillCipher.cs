using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //List<int> plainText = new List<int>() {15, 0, 24, 12, 14, 17, 4, 12, 14, 13, 4, 24};
            //List<int> cipherText = new List<int>() {19,16,18,18,24,15,10,14,16,21,8,22};

            
            List<int> ans = new List<int>() { };
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int l = 0; l < 26; l++)
                        {
                            List<int> key = new List<int>() { };
                            key.Add(i);
                            key.Add(j);
                            key.Add(k);
                            key.Add(l);

                            if (Encrypt(plainText, key).SequenceEqual(cipherText))
                            {
                                ans = key;


                            }

                        }
                    }

                }

            }
            int gcd = 0;
            int b = 0;
            int detKeyMatrix = 0;
            if (ans.Count != 0)
            {

               int c = 0;
               int[,] keyMatrix = new int[2, 2];
               for (int i = 0; i < 2; i++)
               {
                   for (int j = 0; j < 2; j++)
                    {
                        keyMatrix[i, j] = ans[c];
                        c++;
                   }
               }

               //now we will get the variables that should have specific values to make the key valid
                detKeyMatrix = (keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[0, 1] * keyMatrix[1, 0]) ;
                while (detKeyMatrix < 0) detKeyMatrix += 26;
                detKeyMatrix %= 26;
                int temp = detKeyMatrix;
                int a = 26;
                while (a != 0 && temp != 0) // this part gets the gcd between 26 and det(k) which must be one
                {
                    if (a > temp)
                        a %= temp;
                    else
                        temp %= a;
                }

                    gcd = a | temp;
                    for (int i = 1; i < 26; i++) // here you can see the variable b from in this equation b*det(k)% 26 =1
                                                 // we loop trough all possible numbers(only 26 numbers) not big deal o(1)
                    {
                        if ((i * detKeyMatrix) % 26 == 1)
                        {
                            b = i;
                        }
                                                 //then when we find our value we put it into the b 

                    }
                }

                if (ans.Count == 0 || gcd != 1 || detKeyMatrix == 0 || b==0) // these are the condition the shouldn't be met(if met throw exception)
                {

                    throw new InvalidAnlysisException();
                }

                 return ans; // else return the key

            }

        public string Analyse(string plainText, string cipherText)
        {
            List<int> plain = new List<int>() { };
            for (int i = 0; i < plainText.Length; i++)
            {
                plain.Add(plainText[i] - 'a');
            }
            List<int> cipher = new List<int>() { };
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipher.Add(cipherText[i] - 'a');
            }
            string key = "";
            List<int> keyList = Analyse(plain, cipher);
            for (int i = 0; i < keyList.Count; i++)
            {

                key = key.Insert(key.Length, ((char)(keyList[i] + 97)).ToString());
            }
            
            return key;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> result = new List<int>();
            int determinant = 0;
            if (key.Count == 4)
            {
                int[,] matrix = new int[2, 2];
                int idx = 0;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        matrix[j, i] = key[idx++];
                    }
                }
                double detcheck = (matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]);
                while (detcheck < 0) detcheck += 26;
                int Remainder;
                int num1 = 26;
                int num2 = (int)detcheck;
                while (num2 != 0)
                {
                    Remainder = 26 % num2;
                    num1 = num2;
                    num2 = Remainder;
                }

                if (detcheck > 26 || detcheck == 0 || num1 != 1) { throw new SystemException(); }



                int [,] adjmatrix = new int[2, 2];
                adjmatrix[0, 0] = matrix[1, 1];
                adjmatrix[0, 1] = -matrix[0, 1];
                adjmatrix[1, 0] = -matrix[1, 0];
                adjmatrix[1, 1] = matrix[0, 0];

                int a = (int)detcheck, n = 26;
                int id = n, v = 0, d = 1;
                while (a > 0)
                {
                    int t = id / a, x = a;
                    a = id % x;
                    id = x;
                    x = d;
                    d = v - t * x;
                    v = x;
                }
                v %= n;
                if (v < 0) v = (v + n) % n;

                determinant = v;
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        adjmatrix[i, j] *= determinant;
                        adjmatrix[i, j] = ((26 + (((int)adjmatrix[i, j] + 26) % 26))) % 26;
                    }
                }
                int temp = adjmatrix[0, 1];
                adjmatrix[0, 1] = adjmatrix[1, 0];
                adjmatrix[1, 0] = temp;

                //Console.Out.WriteLine(determinant);


                int index2 = 0;

                int ciphercolumn;
                if (cipherText.Count % 2 != 0) { ciphercolumn = (cipherText.Count() + 1) / 2; }
                else { ciphercolumn = cipherText.Count() / 2; }
                int[,] ciphermatrix = new int[2, ciphercolumn];
                for (int i = 0; i < ciphercolumn; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        ciphermatrix[j, i] = cipherText[index2++];
                    }
                }




                int[,] multiplicationcipher = new int[2, ciphercolumn];

                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < ciphercolumn; j++)
                    {
                        //multiplicationcipher[i, j] = 0;
                        for (int k = 0; k < 2; k++)
                        {
                            multiplicationcipher[i, j] += adjmatrix[i, k] * ciphermatrix[k, j];
                            multiplicationcipher[i, j] = multiplicationcipher[i, j] % 26;
                        }

                    }
                }


                for (int j = 0; j < ciphercolumn; j++)
                {
                    for (int i = 0; i < 2; i++) { result.Add((int)multiplicationcipher[i, j] % 26); }
                }
            }

            else
            {
                double[,] matrix = new double[3, 3];
                int idx = 0;
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        matrix[j, i] = key[idx++];
                    }
                }
             

                double detcheck = (
                   matrix[0, 0] * ((matrix[1, 1] * matrix[2, 2]) - (matrix[1, 2] * matrix[2, 1]))
                   )
                   - matrix[0, 1] * ((matrix[1, 0] * matrix[2, 2]) - (matrix[1, 2] * matrix[2, 0]))
                   +
                     matrix[0, 2] * ((matrix[1, 0] * matrix[2, 1]) - (matrix[1, 1] * matrix[2, 0]));
                while (detcheck < 0) detcheck += 26;
                detcheck %= 26;
                int Remainder;
                int num1 = 26;
                int num2 = (int)detcheck;
                while (num2 != 0)
                {
                    Remainder = 26 % num2;
                    num1 = num2;
                    num2 = Remainder;
                }

                //if (detcheck > 26 || detcheck == 0 || num1 == 1) { throw new InvalidAnlysisException(); }

                int a = (int)detcheck, n = 26;
                int id = n, v = 0, d = 1;
                while (a > 0)
                {
                    int t = id / a, x = a;
                    a = id % x;
                    id = x;
                    x = d;
                    d = v - t * x;
                    v = x;
                }
                v %= n;
                if (v < 0) v = (v + n) % n;

                determinant = v;
                double[,] adjointMatrix = new double[3, 3];


                adjointMatrix[0, 0] = (matrix[1, 1] * matrix[2, 2]) - (matrix[1, 2] * matrix[2, 1]);
                adjointMatrix[0, 1] = -((matrix[1, 0] * matrix[2, 2]) - (matrix[1, 2] * matrix[2, 0]));
                adjointMatrix[0, 2] = (matrix[1, 0] * matrix[2, 1]) - (matrix[1, 1] * matrix[2, 0]);

                adjointMatrix[1, 0] = -((matrix[0, 1] * matrix[2, 2]) - (matrix[0, 2] * matrix[2, 1]));
                adjointMatrix[1, 1] = (matrix[0, 0] * matrix[2, 2]) - (matrix[0, 2] * matrix[2, 0]);
                adjointMatrix[1, 2] = -((matrix[0, 0] * matrix[2, 1]) - (matrix[0, 1] * matrix[2, 0]));

                adjointMatrix[2, 0] = ((matrix[0, 1] * matrix[1, 2]) - (matrix[0, 2] * matrix[1, 1]));
                adjointMatrix[2, 1] = (-((matrix[0, 0] * matrix[1, 2]) - (matrix[0, 2] * matrix[1, 0])));
                adjointMatrix[2, 2] = ((matrix[0, 0] * matrix[1, 1]) - (matrix[0, 1] * matrix[1, 0]));

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        adjointMatrix[i, j] *= determinant;
                        adjointMatrix[i, j] = ((26 + (((int)adjointMatrix[i, j]) % 26))) % 26;
                    }
                }


                int index2 = 0;

                int ciphercolumn;
                if (cipherText.Count % 3 != 0) { ciphercolumn = (cipherText.Count() + 2) / 3; }
                else { ciphercolumn = cipherText.Count() / 3; }
                int[,] ciphermatrix = new int[3, ciphercolumn];
                for (int i = 0; i < ciphercolumn; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        ciphermatrix[j, i] = cipherText[index2++];
                    }
                }


                double[,] multiplicationcipher = new double[3, ciphercolumn];
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < ciphercolumn; j++)
                    {
                        multiplicationcipher[i, j] = 0;
                    }
                }

                    for (int i = 0; i < 3; i++)
                    {
                        for (int j = 0; j < ciphercolumn; j++)
                        {
                            for (int k = 0; k < 3; k++)
                            { multiplicationcipher[i, j] += adjointMatrix[i, k] * ciphermatrix[k, j]; }

                        }
                    }



                    for (int j = 0; j < ciphercolumn; j++)
                    {
                        for (int i = 0; i < 3; i++) { result.Add((int)multiplicationcipher[i, j] % 26); }
                    }

                }
                return result;
            }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cipher = new List<int>() { };
            for (int i = 0; i < cipherText.Length; i++)
            {
                cipher.Add(cipherText[i] - 'a');
            }
            List<int> keyy = new List<int>() { };
            for (int i = 0; i < key.Length; i++)
            {
                keyy.Add(key[i] - 'a');
            }

            string plain = "";
            List<int> plainList = Decrypt(cipher, keyy);
            for (int i = 0; i < plainList.Count; i++)
            {

                plain = plain.Insert(plain.Length, ((char)(plainList[i] + 97)).ToString());
            }

            return plain;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //List<int> cipherText = new List<int>();
            //int i = 0;
            //int j = 0;
            //int s = 0;
            //int size = (int)Math.Sqrt(key.Count);
            //for (int x = 0; x <= plainText.Count; x++)
            //{
            //    for (int y = 0; y < size; y++)
            //    {
            //        s += (key[i] * plainText[j]);
            //        i++;
            //        j++;
            //    }
            //    cipherText.Add(s % 26);
            //    s = 0;
            //    if (i == key.Count)
            //        i = 0;
            //    else
            //        j = j - size;
            //}

            //return cipherText;

            List<int> cipherText = new List<int>() { };
            int m = (key.Count % 2 == 0) ? (key.Count / 2) : (key.Count) / 3;
            int[,] keyMatrix = new int[m, m];
            int[,] plainMatrixtmp = new int[plainText.Count / m, m];
            int cnt = 0;
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    keyMatrix[i, j] = key[cnt];
                    cnt++;
                }
            }
            cnt = 0;
            for (int i = 0; i < plainText.Count / m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    plainMatrixtmp[i, j] = plainText[cnt];
                    cnt++;
                }
            }
            int[,] plainMatrix = new int[m, plainText.Count / m];
            for (int i = 0; i < plainText.Count / m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    plainMatrix[j, i] = plainMatrixtmp[i, j];
                }

            }
            int tmp = 0;
            for (int k = 0; k < plainText.Count / m; k++)
            {
                for (int i = 0; i < m; i++)
                {
                    for (int j = 0; j < m; j++)
                    {

                        tmp += keyMatrix[i, j] * plainMatrix[j, k];

                    }

                    tmp = tmp % 26;
                    cipherText.Add(tmp);
                    tmp = 0;
                }

            }
            return cipherText;


        }

        public string Encrypt(string plainText, string key)
        {
            List<int> plain = new List<int>() { };
            for (int i = 0; i < plainText.Length; i++)
            {
                plain.Add(plainText[i] - 'a');
            }
            List<int> keyy = new List<int>() { };
            for (int i = 0; i < key.Length; i++)
            {
                keyy.Add(key[i] - 'a');
            }

            string cipher = "";
            List<int> cipherList = Encrypt(plain, keyy);
            for (int i = 0; i < cipherList.Count; i++)
            {

                cipher = cipher.Insert(cipher.Length, ((char)(cipherList[i] + 97)).ToString());
            }
            cipher = cipher.ToUpper();
            return cipher;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
          
            List<int> result = new List<int>();
            for (int iter = 0; iter < 3; iter++) // number of rows
            {
                for (int x1 = 0; x1 < 26; x1++)// first number of the row
                {
                    for (int x2 = 0; x2 < 26; x2++) // second number of the row
                    {
                        for (int x3 = 0; x3 < 26; x3++)// third number of the row
                        {
                            bool flag = true;
                            for (int i = 0; i < plain3.Count - 1; i += 3) // looping through each number of the plainlist to solve the eqn
                            {
                                if ((x1 * plain3[i] + x2 * plain3[i + 1] + x3 * plain3[i + 2]) % 26 != cipher3[iter + i]) // the eqn of the ct
                                {
                                    flag = false; // if not found flag = false
                                    break;
                                }
                            }
                            if (flag) // if found then add the numbers
                            {
                                result.Add(x1);
                                result.Add(x2);
                                result.Add(x3);
                            }


                        }
                    }
                }
            }
            return result;
        
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            
            List<int> plain = new List<int>() { };
            for (int i = 0; i < plain3.Length; i++)
            {
                plain.Add(plain3[i] - 'a');
            }
            List<int> cipher = new List<int>() { };
            for (int i = 0; i < cipher3.Length; i++)
            {
                cipher.Add(cipher3[i] - 'a');
            }

            string key = "";
            List<int> keyList = Analyse3By3Key(plain, cipher);
            for (int i = 0; i < keyList.Count; i++)
            {

                key = key.Insert(key.Length, ((char)(keyList[i] + 97)).ToString());
            }
            
            return key;
        }
    }
}
