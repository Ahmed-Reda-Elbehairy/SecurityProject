using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        AES.ExtendedEuclid obj = new AES.ExtendedEuclid();
        public long power(int alpha, int k , int q)
        {
            long x = 1;
            for (int i = 0; i < k; i++) x = (x * alpha) % q;
            return x;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> answer = new List<long>();       
            long K = power(y, k, q) % q;
            answer.Add(power(alpha, k, q) % q);
            answer.Add((K * m) % q);
            return answer;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = (int)power(c1, x, q) % q;
            int kinv=obj.GetMultiplicativeInverse(K, q) ;
            return (c2 * kinv ) % q ;
        }
    }
}