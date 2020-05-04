using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace lab3
{
    static class ByKnapsack
    {
        static int encodingSize = 16;
        // Что надо сделать
        // 1. Проверка закрытого ключа на корректность (является ли он сверхвозрастающей послед-тью)
        // 2. Генерация открытого ключа
        // 3. Шифрование текста с помощью открытого ключа
        // 4. Расшифровывание текста с помощью закрытого ключа




        /// <summary>
        /// Проверяет, является ли последовательность чисел сверхвозрастающей. Сортирует последовательность privateKey по возрастанию.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns>Возвращает true в случае, если последовательность privateKey является сверхвозрастающей, и false иначе.</returns>
        static public bool Check(List<int> privateKey)
        {
            privateKey.Sort();

            int sum = 0;
            for (int i = 0; i < privateKey.Count; i++)
            {
                if (privateKey[i] <= sum)
                    return false;
                else
                    sum += privateKey[i];
            }
            return true;
        }

        static private int GCD(int a, int b)
        {
            if (b == 0)
                return a;
            else
                return GCD(b, a % b);
        }

        static public int GCDEx(int a, int b, out int x, out int y)
        {
            if (a == 0)
            {
                x = 0; y = 1;
                return b;
            }
            int x1, y1;
            int d = GCDEx(b % a, a, out x1, out y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;   
        }

        /// <summary>
        /// Генерирует открытый ключ на основании закрытого.
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        static public Tuple<List<int>, int, int> GeneratePublicKey(List<int> privateKey)
        {
            Random R = new Random();

            int sum = privateKey.Sum();
            //int m = sum + R.Next(sum / 4, sum);
            int m = sum + 1;

            int n = m - 1;
            for (int i = m/2; i < m; i++)
                if (GCD(i, m) == 1)
                {
                    n = i; break;
                }

            List<int> publicKey = new List<int>(privateKey.Count);
            for (int i = 0; i < privateKey.Count; i++)
                publicKey.Add((privateKey[i] * n) % m);

            return new Tuple<List<int>, int, int>(publicKey, m, n);
            //return publicKey;
        }

        /// <summary>
        ///  Переводит сообщение s в последовательность бит.
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
        /// Зашифровывает строку text открытым ключом publicKey.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        static public List<int> Encrypt(string text, List<int> publicKey)
        {
            List<bool> binaryText = ToBinary(text);

            while (binaryText.Count % publicKey.Count != 0)
                binaryText.Add(false);

            LinkedList<int> encyptedText = new LinkedList<int>();

            for (int i = 0; i < binaryText.Count / publicKey.Count; i++)
            {
                int sum = 0;
                for (int j = 0; j < publicKey.Count; j++)
                    sum += binaryText[i * publicKey.Count + j] ? publicKey[j] : 0;

                encyptedText.AddLast(sum);
            }

            return encyptedText.ToList();
        }

        /// <summary>
        /// Возвращает решение задачи о рюкзаке - выбирает из privateKey такие элементы, что их сумма равна ch.
        /// </summary>
        /// <param name="ch"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        static private bool[] KnapsackProblemResult(int ch, List<int> privateKey)
        {
            bool[] result = new bool[privateKey.Count];

            for (int i = privateKey.Count - 1; i >= 0; i--)
            {
                result[i] = (ch >= privateKey[i]);

                if (result[i])
                    ch -= privateKey[i];
            }

            if (ch > 0)
                return null;
            return result;
        }

        /// <summary>
        /// Расшифровывает сообщение text в соответствии с приватным ключом privateKey.
        /// </summary>
        /// <param name="text"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        static public string Decrypt(List<int> text, List<int> privateKey, int n, int m)
        {
            LinkedList<bool> binaryTextLL = new LinkedList<bool>();

            int reverseN, sup;
            GCDEx(n, m, out reverseN, out sup);
            reverseN = (reverseN % m + m) % m;

            for (int i = 0; i < text.Count; i++)
            {
                int a = text[i] * reverseN % m;
                bool[] knapsack = KnapsackProblemResult(a, privateKey);

                for (int j = 0; j < privateKey.Count; j++)
                //for (int j = privateKey.Count - 1; j >= 0; j--)
                    binaryTextLL.AddLast(knapsack[j]);
            }

            List<bool> binaryText = binaryTextLL.ToList();

            StringBuilder result = new StringBuilder(binaryText.Count / encodingSize);

            for (int i = 0; i < binaryText.Count / encodingSize; i++)
            {
                int ch = 0;

                for (int j = encodingSize - 1; j >= 0; j--)
                {
                    ch <<= 1;
                    ch += binaryText[i * encodingSize + j] ? 1 : 0;
                }

                result.Append((char)ch);
            }

            return result.ToString();
        }
    }
}
