using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;
using System.Linq;

namespace lab3
{
    static class RSA
    {
        static int encodingSize = 16;

        /// <summary>
        /// Расширенный Алгоритм Евклида.
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <returns></returns>
        static public BigInteger GCDEx(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
        {
            if (a == 0)
            {
                x = 0; y = 1;
                return b;
            }
            BigInteger x1, y1;
            BigInteger d = GCDEx(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }

        /*
        /// <summary>
        /// Проверка числа a на простоту.
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        static public bool Check(UInt32 a)
        {
            return true;
        }
        */

        /// <summary>
        /// Возвращает закрытый и открытый ключи (d, n, e) в зависимости от двух простых чисел p и q.
        /// </summary>
        /// <param name="p"></param>
        /// <param name="q"></param>
        /// <returns></returns>
        static public Tuple<BigInteger, BigInteger, BigInteger> GenerateKeys(BigInteger p, BigInteger q)
        {
            BigInteger n = p * q;
            //BigInteger e = 13;
            //BigInteger e = 79;
            BigInteger e = 65537;

            BigInteger d, sup;
            BigInteger m = (p - 1) * (q - 1);
            BigInteger g = GCDEx(e, m, out d, out sup);

            if (g != 1)
                throw new Exception("");
            d = (d % m + m) % m;

            return new Tuple<BigInteger, BigInteger, BigInteger>(d, n, e);
        }

        /// <summary>
        /// Возвращает разрядность числа в двоичной СС.
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        static private int GetNumberSize(BigInteger a)
        {
            return (int)(BigInteger.Log10(a) * Math.Log(10) / Math.Log(2));
        }

        /// <summary>
        /// Переводит сообщение s в последовательность бит.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        static private List<bool> ToBinary(string s)
        {
            List<bool> binaryText = new List<bool>(s.Length * encodingSize);
            for (int i = 0; i < s.Length; i++)
            {
                int a = s[i];

                for (int j = 0; j < encodingSize; j++)
                {
                    binaryText.Add((a % 2) == 1);
                    a >>= 1;
                }
            }

            return binaryText;
        }

        /// <summary>
        /// Переводит 64-разрядное число в последовательность бит.
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        static public List<bool> ToBinary(BigInteger a, int size)
        {
            List<bool> binaryText = new List<bool>(size);
            for (int i = 0; i < size; i++)
            {
                binaryText.Add((a % 2) == 1);
                a >>= 1;
            }

            return binaryText;
        }

        /// <summary>
        /// Переводит последовательность бит в 64-разрядное целое число.
        /// При этом элементы в начале последовательности считаются старшими разрядами.
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        static public BigInteger BinaryToInt64(List<bool> b)
        {
            BigInteger result = 0;

            for (int i = 0; i < b.Count; i++)
            {
                result <<= 1;
                result += b[i] ? 1 : 0;
            }

            return result;
        }

        static public BigInteger ModularExp(BigInteger a, BigInteger e, BigInteger m)
        {
            BigInteger result = 1;

            List<bool> bin = ToBinary(e, 64);
            for (int i = bin.Count - 1; i >= 0; i--)
            {
                result *= result;
                result %= m;
                if (bin[i])
                    result *= a;
                result %= m;
            }

            return result;

        }


        /// <summary>
        /// Зашифровывает сообщение text в соответствии с открытым ключом (n, e).
        /// </summary>
        /// <param name="n"></param>
        /// <param name="e"></param>
        /// <param name="text"></param>
        /// <returns></returns>
        static public List<BigInteger> Encrypt(BigInteger n, BigInteger e, string text)
        {
            int blockSize = GetNumberSize(n) - 2;

            List<bool> binaryText = ToBinary(text);
            while (binaryText.Count % blockSize != 0)
                binaryText.Add(false);

            List<BigInteger> result = new List<BigInteger>(text.Length);

            for (int i = 0; i < binaryText.Count; i += blockSize)
            {
                List<bool> curBlock = binaryText.Skip(i).Take(blockSize).ToList();
                BigInteger mi = BinaryToInt64(curBlock);
                BigInteger ci = ModularExp(mi, e, n);
                result.Add(ci);
            }

            return result;
        }

        /// <summary>
        /// Расшифровывает сообщение text в соответствии с приватным ключом d и значением n публичного ключа.
        /// </summary>
        /// <param name="d"></param>
        /// <param name="n"></param>
        /// <param name="text"></param>
        /// <returns></returns>
        static public string Decrypt(BigInteger d, BigInteger n, List<BigInteger> text)
        {
            int blockSize = GetNumberSize(n) - 2;

            List<bool> binaryText = new List<bool>(text.Count * blockSize);

            for (int i = 0; i < text.Count; i++)
            {
                BigInteger ci = text[i];
                BigInteger mi = ModularExp(ci, d, n);

                List<bool> bin = ToBinary(mi, blockSize); bin.Reverse();
                binaryText.InsertRange(binaryText.Count, bin);
            }

            StringBuilder result = new StringBuilder(binaryText.Count / encodingSize);

            for (int i = 0; i < binaryText.Count; i += encodingSize)
            {
                List<bool> curBlock = binaryText.Skip(i).Take(encodingSize).ToList();
                curBlock.Reverse();

                char curCh = (char)BinaryToInt64(curBlock);
                result.Append(curCh);
            }

            return result.ToString();
        }
    }
}
