using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public int power(int m, int e, int n)
        {
            int x = 1;
            for (int i = 0; i < e; i++) x = (x * m) % n;
            return x;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int YB = power(alpha, xb, q) % q;
            List<int> ans = new List<int>();
            int K = power(YB, xa, q) % q;
            ans.Add(K);
            ans.Add(K);
            return ans;
        }
    }
}