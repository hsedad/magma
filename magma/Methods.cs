using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace magma
{
    internal class Methods
    {
        public uint uint_from_bytes(byte[] input, int index) // метод собирает 32 битовое число из массива байт[4]
        {
            uint result = 0;
            result |= input[index];
            result <<= 8; result &= 0xffffff00;
            result |= input[index + 1];
            result <<= 8; result &= 0xffffff00;
            result |= input[index + 2];
            result <<= 8; result &= 0xffffff00;
            result |= input[index + 3];
            return result;

        }

        public ulong ulong_from_bytes(byte[] input, int index) // метод собирает 64 битовое число из массива байт[8]
        {
            ulong result = 0;
            result |= input[index];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 1];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 2];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 3];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 4];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 5];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 6];
            result <<= 8; result &= 0xffffffffffffff00;
            result |= input[index + 7];
            return result;
        }

        public byte[] bytes_from_uint(uint input) // метод раскладывает 32 битное число в массив байт[4]
        {
            byte[] result = new byte[4];
            result[3] = (byte)input;
            result[2] = (byte)(input >> 8);
            result[1] = (byte)(input >> 16);
            result[0] = (byte)(input >> 24);
            return result;
        }

        public byte[] bytes_from_ulong(ulong input)  // метод раскладывает 64 битное число в массив байт[8]
        {
            byte[] result = new byte[8];
            result[7] = (byte)input;
            result[6] = (byte)(input >> 8);
            result[5] = (byte)(input >> 16);
            result[4] = (byte)(input >> 24);
            result[3] = (byte)(input >> 32);
            result[2] = (byte)(input >> 40);
            result[1] = (byte)(input >> 48);
            result[0] = (byte)(input >> 56);
            return result;
        }

        public uint replace_K(uint in_data)  // функция осуществляющая подстановку 4 битных значений из таблицы К
        {
            byte[,] K_table = new byte[8, 16] // таблица блока перестановок К по ГОСТ 34.12-2015
            {
               //  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
                {  1, 7,14,13, 0, 5, 8, 3, 4,15,10, 6, 9,12,11, 2},//0
                {  8,14, 2, 5, 6, 9, 1,12,15, 4,11, 0,13,10, 3, 7},//1
                {  5,13,15, 6, 9, 2,12,10,11, 7, 8, 1, 4, 3,14, 0},//2
                {  7,15, 5,10, 8, 1, 6,13, 0, 9, 3,14,11, 4, 2,12},//3
                { 12, 8, 2, 1,13, 4,15, 6, 7, 0,10, 5, 3,14, 9,11},//4
                { 11, 3, 5, 8, 2,15,10,13,14, 1, 7, 4,12, 9, 6, 0},//5
                {  6, 8, 2, 3, 9,10, 5,12, 1,14, 4, 7,11,13, 0,15},//6
                { 12, 4, 6, 2,10, 5,11, 9,14, 8,13, 7, 0, 3,15, 1} //7
            };

            byte[] inbytes, outbytes;  // массивы байт для 32 разрядного значения
            inbytes = bytes_from_uint(in_data);  // заполняем этот массив
            outbytes = new byte[4];  // массив байт для размещения результата перестановки
            for (int i = 0; i < 4; i++)  // проходим поочередно по всем 4 входящим байтам
            {
                byte h_part = (byte)((inbytes[i] & 0xF0) >> 4);  // получаем старшую часть байта
                byte l_part = (byte)(inbytes[i] & 0x0F);   // получаем  младшую часть байта
                h_part = K_table[i * 2, h_part];  // делаем подстановку старшей части байта
                l_part = K_table[i * 2 + 1, l_part];  // делаем подстановку младшей части байта
                outbytes[i] = (byte)((h_part << 4) | l_part);  // записываем обе 4 битные части в исходящий байт
            }
            return uint_from_bytes(outbytes, 0);  // возвращаем 32 битное значение после перестановок
        }

        public uint add_mod2_32(uint a, uint b) // функция сложения в кольце вычетов по модулю 2 в степени 32
        {
            ulong result = a + b; // складываем входящие значения
            return (uint)result; // отбрасываем переполнение
        }

        public ulong crypt(ulong in_data, uint[] session_keys)  // собственно функция за(рас)шифрования
        {
            ulong result; // возвращаемое 64 битное значение
            uint case1, case2, temp;  // регистры 1, 2 и промежуточный
            case1 = (uint)(in_data & 0x00000000FFFFFFFF);  // Выделяем младшие 32 бита
            case2 = (uint)(in_data >> 32);  // Выделяем старшие 32 бита
            for (int i = 0; i < 32; i++)  // Производим 32 итерации
            {
                temp = add_mod2_32(case1, session_keys[i]);  // сложение сессионного ключа и регистра 1 по модулю 2 в степени 32
                temp = replace_K(temp);  // выполняем преобразование К (замену значений)
                temp = (temp << 11) | (temp >> 21);  // выполняем циклический сдвиг влево на 11 разрядов
                temp = temp ^ case2;  // выполняем побитовое сложение по модулю 2 с содержимым регистра 2
                case2 = case1;  // содержимое регистра 2 заполняем содержимым регистра 1
                case1 = temp;  // регистр 1 заполняем результатом преобразований
            }
            result = case1; // содержимое регистров (меняя их местами) заносим в результат
            result = result << 32;
            result = result | case2;
            return result;
        }

        public ulong[] read_from_file(string filename) // метод читает из файла массив из 64 битных значений
        {
            ulong[] result;
            byte[] bytes = File.ReadAllBytes(filename); // читаем файл сообщения в массив байт

            if ((bytes.Length % 8) != 0) // проверяем сообщение на кратность 64 битам
            {
                byte[] zero_tail = new byte[8 - bytes.Length % 8];  // доп массив для обеспечения кратности длины входящего массива байт 64 битам
                for (int i = 0; i < zero_tail.Length; i++) zero_tail[i] = 0; // заполняем "хвост" нулями
                bytes = bytes.Concat(zero_tail).ToArray();  //добавляем нулевой "хвост" в конец массива байт сообщения
            }

            result = new ulong[(int)(bytes.Length / 8)];  // массив из блоков по 64 бит исходного сообщения
            for (int i = 0; i < (bytes.Length - 7); i += 8)  // заполняем массив из блоков по 64 бит из массива байт
            {
                result[(int)(i / 8)] = ulong_from_bytes(bytes, i);
            }
            return result;
        }

        public byte[] abyte_from_aulong(ulong[] aulong) 
        {
            byte[] result = bytes_from_ulong(aulong[0]);
            for (int i = 1;i < aulong.Length;i++)
            {
                result = result.Concat(bytes_from_ulong(aulong[i])).ToArray();
            }
            return result;
        }
    }
}
