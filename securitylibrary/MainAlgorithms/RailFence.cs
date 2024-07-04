using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            
          
            int ans = 0;
            for (int i = 1; i <= plainText.Length; i++)
            {

                if (string.Compare(Encrypt(plainText, i), cipherText) == 0)
                {
                    ans = i; break;
                }


            }
            return ans;
        }

        public string Decrypt(string cipherText, int key)
        {
            int k = key;
            string pt = cipherText;
            pt = pt.ToLower();
            double o = pt.Length;
            double n = k;
            double col = (o / n);



            col = Math.Ceiling(col);
            int y = Convert.ToInt32(col);

            char[,] arr = new char[k, y];
            int counter = 0;
            //int num = key * y;

            for (int i = 0; i < k; i++)
            {
                for (int j = 0; j < y; j++)
                {
                    if (counter < pt.Length)
                    {
                        arr[i, j] = pt[counter];
                        counter++;
                    }
                }

            }


            List<char> ct = new List<char>();

            for (int i = 0; i < y; i++)
            {

                for (int j = 0; j < k; j++)
                {

                    ct.Add(arr[j, i]);

                }


            }


            var v = string.Join("", ct.ToArray());
            v = v.ToUpper();

            return v;
        }

        public string Encrypt(string plainText, int key)
        {
            int k = key;
            string pt = plainText;
            pt = pt.ToLower();

            double o = pt.Length;
            double n = k;
            double col = (o / k);

            col = Math.Ceiling(col);
            int y = Convert.ToInt32(col);

            char[,] arr = new char[k, y];
            int counter = 0;
            //int num = key * y;

            for (int i = 0; i < y; i++)
            {
                for (int j = 0; j < k; j++)
                {
                    if (counter < pt.Length)
                    {
                        arr[j, i] = pt[counter];
                        counter++;
                    }
                }

            }


            List<char> ct = new List<char>();

            for (int i = 0; i < k; i++)
            {

                for (int j = 0; j < y; j++)
                {

                    ct.Add(arr[i, j]);

                }


            }


            var v = string.Join("", ct.ToArray());
            v = v.ToUpper();

            return v;
        }
    }
}
