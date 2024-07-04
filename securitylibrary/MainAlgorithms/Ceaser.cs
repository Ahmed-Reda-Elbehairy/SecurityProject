using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //we will add the value of the key then we use % 26 to make sure that the chars are in our range
            string output_text = "";
            int output_index = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (char.IsUpper(plainText[i]))
                {
                    //ascii code of A=65
                    //index of p.x=ascii of char -A    ,      + key  to get index of cipher text then %26
                    //ciper text=index of c.t + A
                    output_index = ((int)((plainText[i] + key) - 'A') % 26 + 'A');
                    output_text += (char)output_index;
                }
                else
                {
                    output_index = ((int)((plainText[i] + key) - 'a') % 26 + 'a');
                    output_text += (char)output_index;
                }
            }
           
            return output_text;

        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = ""; // the answer
            cipherText = cipherText.ToLower(); // converting the CT to lower case
            
            for (int i = 0; i < cipherText.Length; i++)
            {
                if ((int)(cipherText[i]) - key >= 97)   
                {
                    plainText = plainText.Insert(plainText.Length, ((char)(((int)(cipherText[i]) - key))).ToString()); // we only minus the key if the value of CT char - key will be less than the asciicode of 'a' 
                }
                else
                    plainText = plainText.Insert(plainText.Length, ((char)(((int)(cipherText[i]) - key + 26))).ToString());// if it's less than the asciicode of 'a' we the add 26 'the size of the alphabets'
            }
            
            return plainText ;
        }



        public int Analyse(string plainText, string cipherText)
        {
            // getting the key then adding the 26 value untill the value of the key become positive (the first +ve)
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();

            int plain_index = plainText[0];
            int cipher_index = cipherText[0];
            int key = (cipher_index - plain_index) % 26;
            while (plainText.Length > 0 && cipherText.Length > 0)
            {
                if (key < 0)
                {
                    key += 26;
                }
                else
                    break;

                
            }

            return key;
        }
    }
}

