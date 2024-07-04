using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.RSA
{
    public class RSA
    {
        AES.ExtendedEuclid obj = new AES.ExtendedEuclid();
        public int power(int m, int e, int n)
        {
            int x = 1;
            for (int i = 0; i < e; i++) x = (x * m) % n;
            return x;
        }
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return  power(M,e,n)%n;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phin = (p - 1) * (q - 1);
            int d =obj.GetMultiplicativeInverse(e, phin);
            return power(C, d, n) % n;
        }
    }
}