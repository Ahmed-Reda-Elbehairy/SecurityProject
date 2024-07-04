using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            SortedDictionary<int, char> indexCharPairs = new SortedDictionary<int, char>();// map of the index of each char appeared in the cipher text
            Dictionary<char, int> alphabet = new Dictionary<char, int>();
            for (int i = 0; i < 26; i++)
            {

                alphabet[(char)(i + 97)] = 0;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (plainText[i] >= 'a' && plainText[i] <= 'z')
                {
                    indexCharPairs[plainText[i] - 'a'] = cipherText[i]; // index of the char in alphabet and its corresponding char in the CT
                }
            }
            //from to 52 will check if the index of char in alphabet is not in the list and will add the key attached with the next char in order just if it is not allready in the list
            char tmp = ' '; // indicates the current char
            for (int i = 0; i <= 25; i++)
            {

                if (!indexCharPairs.ContainsKey(i))
                {
                    if (tmp != 'z' && !indexCharPairs.ContainsValue((char)(tmp + 1 % ('z' + 1))))
                    {
                        indexCharPairs.Add(i, (char)(tmp + 1 % ('z' + 1)));
                    }
                    else if (indexCharPairs.ContainsValue((char)(tmp + 1 % ('z' + 1))))
                    {
                        indexCharPairs[i] = ' ';
                    }
                    else
                        if (!indexCharPairs.ContainsValue('a'))
                    {
                        indexCharPairs.Add(i, 'a');
                    }

                }
                if (indexCharPairs[i] != ' ') tmp = indexCharPairs[i]; //updating the current char
            }
            Dictionary<char, int> notFound = new Dictionary<char, int>(); //map of the chars that is not added in the index char pairs
            foreach (var item in alphabet.Keys.ToList())
            {
                foreach (var item2 in indexCharPairs.Values)
                {
                    if (item == item2)
                    {
                        alphabet[item] = 1; // making the value 1 to indicate that it's been found
                    }
                }

            }
            foreach (var item in alphabet)
            {
                if (item.Value == 0)
                {
                    notFound.Add(item.Key, 0);//adding the chars with value 0
                }
            }
            // from 73 to 84 will carry the order of each 'notFound char' in the pt (order of chars in PT)
            int order = 1;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (notFound.ContainsKey(plainText[i]))
                {
                    if (notFound[plainText[i]] == 0)
                    {
                        notFound[plainText[i]] = order;
                        order++;
                    }
                }
            }
            var sortedNotFound = from entry in notFound orderby entry.Value ascending select entry; // sorts the notFound based on the order in the PT
            foreach (var item in indexCharPairs.Keys.ToList())
            {
                foreach (var item2 in sortedNotFound)
                {
                    if (indexCharPairs[item] == ' ' && item2.Value != 0 && !indexCharPairs.ContainsValue(item2.Key)) // only the chars thats found in PT and not found in the indexcharpairs will be inserted in the index char pairs list based on their order in the PT
                    {
                        indexCharPairs[item] = item2.Key;


                    }
                }
            }
            foreach (var item in indexCharPairs.Keys.ToList())
            {
                foreach (var item2 in sortedNotFound)
                {
                    if (indexCharPairs[item] == ' ' && item2.Value == 0 && !indexCharPairs.ContainsValue(item2.Key))
                    {
                        indexCharPairs[item] = item2.Key; // inserting the rest ot the notFound chars and also not found in the PT but this time with their order in alphabets


                    }
                }
            }

            foreach (var item in indexCharPairs)
            {
                key = key.Insert(key.Length, (item.Value).ToString()); //inserting each value of the indexcharpairs in the key string

            }
            return key; 
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {

                plainText = plainText.Insert(plainText.Length, ((char)('a' + key.IndexOf(cipherText[i]))).ToString());//replacing the index of the CT char with its corresponding char in the key (the ith char in the pt will be replaced with the ith char in the key)
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] >= 'a' && plainText[i] <= 'z')
                {

                    cipherText = cipherText.Insert(cipherText.Length, key[plainText[i] - 'a'].ToString());// index of the PT char in the alphabets will be replaced in the corresponding index in the key 
                }
            }
            cipherText = cipherText.ToUpper();
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string plainText = "";

            cipher = cipher.ToLower();
            string key = "etaoinsrhldcumfpgwybvkxjqz"; // here we will use the char frequency as our key to produce the PT
            Dictionary<char, int> frequencyDict = new Dictionary<char, int>(); // a frequency map to save each char with its frequency
            SortedDictionary<int, List<char>> frequencyDictInverted = new SortedDictionary<int, List<char>>(); // inverted map of the first map just to save each
                                                                                                               // frequency number with a list of characters
                                                                                                               // appeared that number of times
            for (int i = 0; i < cipher.Length; i++)
            {

                frequencyDict[cipher[i]] = 0; // initializing each key to the value '0' to increase them 
            }


            for (int i = 0; i < cipher.Length; i++)
            {

                frequencyDict[cipher[i]]++; // giving each char its number of appearance
            }

            foreach (var item in frequencyDict)
            {
                frequencyDictInverted[item.Value] = new List<char>() { }; // initializing each key with an empty list
            }
            foreach (var item in frequencyDict)
            {
                frequencyDictInverted[item.Value].Add(item.Key); // adding the character value to the list of each number
            }

            var frequencyDictInvertedDescending = frequencyDictInverted.OrderByDescending(frequencyDictInverted1 => frequencyDictInverted1.Key); //ordering the map in descending order to be with the same logic as the char frequency
            var x = frequencyDictInvertedDescending.ToDictionary(xx => xx.Key, xx => xx.Value.ToList()); // converting 'frequencyDictInvertedDescending' back to map

            int order = 0; // variable to indicate the order of the char we are at 
            SortedDictionary<int, char> ans = new SortedDictionary<int, char>(); // the values of this map will be our PT
            foreach (var item in x.Values) // looping through the lists  keys
            {

                for (int i = 0; i < item.Count; i++) // looping through items of each list
                {
                    for (int j = 0; j < cipher.Length; j++) // looping through the cipher text to compare it with the key
                    {
                        if (item[i] == cipher[j])
                        {
                            ans[j] = key[order + i]; // adding the value of the character at its corresponding position in the list (adding i on the order in case of an equal frequencies)

                        }

                    }
                }
                order++;//increasing the level to know what char of the key to add
            }
            foreach (var item in ans)
            {
                plainText = plainText.Insert(plainText.Length, item.Value.ToString()); // inserting the values of the ans map to the plaintext 

            }

        return plainText; // returning the answer
        }
    }
}