using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace lab3
{
    class Program
    {
        static int GetInt(string warning)
        {
            bool ka; int p;
            do {
                string s = Console.ReadLine();
                ka = Int32.TryParse(s, out p);
                if (ka == false || p < 1)
                    Console.WriteLine(warning);
            } while (ka == false || p < 1);
            return p;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Какой способ ассиметричного шифрования вы хотите использовать? " +
                "Нажмите R, если вы хотите использовать самописный RSA, K, если вы хотите использовать алгоритм на основе задачи об упакове рюкзака, и N, если хотите использовать библиотечный RSA");
            char ch;
            do {
                ch = Console.ReadKey().KeyChar;
                Console.CursorLeft = 1;
                if (ch == 'R')
                { Task2(); break; }
                else if (ch == 'K')
                { Task1(); break; }
                else if (ch == 'N')
                { Task3(); break; }
            } while (true);

            Console.ReadKey();
        }

        static void Task2()
        {
            // Запрашиваем пару чисел (p, q) ключ
            Console.WriteLine("Введите значение простого числа p:");
            int p = GetInt("Введите корректное положительное число.");
            Console.WriteLine("Введите значение простого числа q:");
            int q = GetInt("Введите корректное положительное число.");


            // Генерируем закрытый и открытый ключи
            Tuple<BigInteger, BigInteger, BigInteger> T1 = RSA.GenerateKeys(p, q);

            Console.WriteLine("На основании пары чисел (p, q) были сгенерированы приватный и публичный ключи.");
            Console.WriteLine("Приватный ключ (d, n):");
            Console.WriteLine($"d = {T1.Item1}, n = {T1.Item2}");
            Console.WriteLine("Публичный ключ (e, n):");
            Console.WriteLine($"e = {T1.Item3}, n = {T1.Item2}");


            // Запрашиваем путь к файлу с текстом, который необходимо зашифровать
            Console.WriteLine("Укажите имя текстового файла с текстом, который необходимо зашифровать:");
            string path;
            string textBefore;
            do {
                try
                {
                    path = Console.ReadLine();
                    textBefore = File.ReadAllText(path);
                    break;
                }
                catch
                {
                    Console.WriteLine("Указанный вами файл не существует =(");
                    Console.WriteLine("Попробуйте снова");
                }
            } while (true);


            // Шифруем и показываем текст с помощью публичного ключа:
            List<BigInteger> cryptoText = RSA.Encrypt(T1.Item2, T1.Item3, textBefore);
            Console.WriteLine("Зашифрованное сообщение:");
            for (int i = 0; i < cryptoText.Count; i++)
                Console.Write(cryptoText[i].ToString() + " ");
            Console.WriteLine();


            // Расшифровываем и показываем зашифрованный текст с помощью приватного ключа
            string text = RSA.Decrypt(T1.Item1, T1.Item2, cryptoText);
            Console.WriteLine("Расшифрованный текст:");
            Console.WriteLine(text);
        }

        static void Task1()
        {
            // Запрашиваем приватный ключ
            Console.WriteLine("Введите приватный ключ. Во-первых, укажите длину ключа:");
            int size = GetInt("Введите корректное положительное число.");

            List<int> privateKey = new List<int>(size);
            for (int i = 0; i < size; i++)
            {
                Console.WriteLine("Введите " + i + "-е число приватного ключа");
                privateKey.Add(GetInt("Введите корректное положительное число."));
            }

            // Проверяем публичный ключ на корректность
            bool isOk = ByKnapsack.Check(privateKey);
            if (!isOk)
            {
                Console.WriteLine("Введённый вами ключ не является сверхвозрастающей последовательностью =(");
                Console.ReadKey();
                return;
            }

            // Генерируем и показываем публичный ключ
            Tuple<List<int>, int, int> T1 = ByKnapsack.GeneratePublicKey(privateKey);

            List<int> publicKey = T1.Item1;
            int m = T1.Item2, n = T1.Item3;

            Console.WriteLine("На основании приватного ключа сгенерировался следующий публичный ключ:");
            for (int i = 0; i < publicKey.Count; i++)
                Console.Write(publicKey[i].ToString() + " ");
            Console.WriteLine();


            // Запрашиваем путь к файлу с текстом, который необходимо зашифровать
            Console.WriteLine("Укажите имя текстового файла с текстом, который необходимо зашифровать:");
            string path;
            string textBefore;
            do {
                try
                {
                    path = Console.ReadLine();
                    textBefore = File.ReadAllText(path);
                    break;
                }
                catch
                {
                    Console.WriteLine("Указанный вами файл не существует =(");
                    Console.WriteLine("Попробуйте снова");
                }
            } while (true);


            // Шифруем и показываем текст с помощью публичного ключа:
            List<int> cryptoText = ByKnapsack.Encrypt(textBefore, publicKey);
            Console.WriteLine("Зашифрованное сообщение:");
            for (int i = 0; i < cryptoText.Count; i++)
                Console.Write(cryptoText[i].ToString() + " ");
            Console.WriteLine();


            // Расшифровываем и показываем зашифрованный текст с помощью приватного ключа
            string text = ByKnapsack.Decrypt(cryptoText, privateKey, n, m);
            Console.WriteLine("Расшифрованный текст:");
            Console.WriteLine(text);
        }

        static void Task3()
        {
            using (RSACryptoServiceProvider rsa_csp = new RSACryptoServiceProvider(2048))
            {
                Console.WriteLine("Хотите использовать уже имеющиеся приватный и публичный ключи (Y)? " +
                    "Нажмите (N), если хотите сгенерировать новые. В этом случае они сохранятся в файл xmlstring.txt.");
                char ch;
                do {
                    ch = Console.ReadKey().KeyChar;
                    Console.CursorLeft = 1;
                    if (ch == 'Y')
                    {
                        // Запрашиваем путь к файлу с ключами
                        Console.WriteLine("Укажите имя текстового файла с ключами:");
                        string path;
                        string xmlString;
                        do {
                            try
                            {
                                path = Console.ReadLine();
                                xmlString = File.ReadAllText(path);
                                break;
                            }
                            catch
                            {
                                Console.WriteLine("Указанный вами файл не существует =(");
                                Console.WriteLine("Попробуйте снова");
                            }
                        } while (true);

                        rsa_csp.FromXmlString(xmlString);
                        break;
                    }
                    else if(ch == 'N')
                    {
                        string xmlString = rsa_csp.ToXmlString(true);
                        File.WriteAllText("xmlstring.txt", xmlString);
                        break;
                    }
                } while (true);



                // Запрашиваем путь к файлу с текстом, который необходимо зашифровать
                Console.WriteLine("Укажите имя текстового файла с текстом, который необходимо зашифровать:");
                string path2;
                string textBefore;
                do {
                    try
                    {
                        path2 = Console.ReadLine();
                        textBefore = File.ReadAllText(path2);
                        break;
                    }
                    catch
                    {
                        Console.WriteLine("Указанный вами файл не существует =(");
                        Console.WriteLine("Попробуйте снова");
                    }
                } while (true);



                // Зашифровываем текст блоками по 224 байта в соответствии с открытым ключом
                List<byte> encryptedData = new List<byte>();

                for (int i = 0; i < textBefore.Length; i += RSANet.blockSize / 2)
                {
                    string curStr;
                    if (i + RSANet.blockSize / 2 > textBefore.Length)
                        curStr = textBefore.Substring(i);
                    else
                        curStr = textBefore.Substring(i, RSANet.blockSize / 2);

                    byte[] curByteBlock = RSANet.StringToBytes(curStr); // ByteConverter.GetBytes(curStr);
                    byte[] curEncryptedData = RSANet.Encrypt(curByteBlock, rsa_csp.ExportParameters(false), false);
                    encryptedData.InsertRange(encryptedData.Count, curEncryptedData);
                }



                // Выводим зашифрованное сообщение на экран
                Console.WriteLine("Зашифрованное сообщение:");
                for (int i = 0; i < encryptedData.Count; i++)
                    Console.Write(encryptedData[i] + " ");
                Console.WriteLine();



                // Расшифровываем текст в соответствии с закрытым ключом
                StringBuilder decryptedData = new StringBuilder();

                int blockSize = 256;
                for (int i = 0; i < encryptedData.Count; i += blockSize)
                {
                    byte[] curByteBlock = encryptedData.Skip(i).Take(blockSize).ToArray();
                    byte[] curDecryptedData = RSANet.Decrypt(curByteBlock, rsa_csp.ExportParameters(true), false);

                    decryptedData.Append(RSANet.BytesToString(curDecryptedData)); //  Encoding.Un.GetString(curDecryptedData));
                }



                // Выводим расшифрованное сообщение на экран
                Console.WriteLine("Расшифрованный текст:");
                Console.WriteLine(decryptedData);
            }
        }
    }
}
