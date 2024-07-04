using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        int iter = 0;
        List<List<int>> table = new List<List<int>>();
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetInverse(int number, int baseN)
        {
            if (iter == 0)
            {
                List<int> values = new List<int>();
                values.Add(0);
                values.Add(1);
                values.Add(0);
                values.Add(baseN);
                values.Add(0);
                values.Add(1);
                values.Add(number);
                table.Add(values);
            }
            if (table[iter][6] == 1)
            {
                return table[iter][5];
            }
            if (table[iter][6] == 0) return -1;

            int qNext = table[iter][3] / table[iter][6];
            iter++;
            List<int> values2 = new List<int>();
            values2.Add(qNext);
            values2.Add(table[iter - 1][4]);
            values2.Add(table[iter - 1][5]);
            values2.Add(table[iter - 1][6]);
            values2.Add(table[iter - 1][1] - qNext * table[iter - 1][4]);
            values2.Add(table[iter - 1][2] - qNext * table[iter - 1][5]);
            values2.Add(table[iter - 1][3] - qNext * table[iter - 1][6]);
            table.Add(values2);
            return GetInverse(number, baseN);


        }
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            
            int inv = GetInverse(number, baseN);
            if (inv == -1)
            {
                return -1;
            }            
            while (inv < 0) inv += baseN;
            return inv % baseN;
        }
    }

}
