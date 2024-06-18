using System.Linq.Expressions;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using magma;

bool encrypt = false, decrypt = false;
string message_file = "message.txt";
string cipher_file = "cipher.dat";
string key_file = "magma.key";

if (args.Length != 4) // проверяем количество аргументов консольного приложения и их корректность
{ 
    Console.WriteLine("Using program: magma -e input file -k key file for encryption");
    Console.WriteLine("Using program: magma -d input file -k key file for decryption");
}
else
{
    if (!args[0].Contains("-e") & !args[0].Contains("-d"))
    { Console.WriteLine("Using program: magma -e(-d) input file -k key file"); return; }
    if (!args[2].Contains("-k"))
    { Console.WriteLine("Using program: magma -e(-d) input file -k key file"); return; }
    if (!File.Exists(args[1]))
    { Console.WriteLine("File for encryption/decryption not found"); return; }
    if (!File.Exists(args[3]))
    { Console.WriteLine("Key file not found"); return; }
    if (args[0] == "-e") {encrypt = true; message_file = args[1]; }
    if (args[0] == "-d") {decrypt = true; cipher_file = args[1]; }
    key_file = args[3];
}

Methods cs = new Methods(); // подключаем файл со вспомогательными методами Methods.cs

byte[] key_bytes = File.ReadAllBytes(key_file);  // читаем ключ из файла в массив байт
if (key_bytes.Length != 32)
{
    Console.WriteLine("Длина ключа не равна 256 бит, проверьте файл ключа " + key_file);
    return;
}
uint[] key = new uint[8]; // ключ шифрования из 32 разрядных значений
for (int i = 0; i < 8; i++) key[i] = cs.uint_from_bytes(key_bytes, i * 4); // заполняем ключ шифрования значениями из массива байт

uint[] enc_session_key = new uint[32];  // массив сессионных ключей зашифрования
uint[] dec_session_key = new uint[32];  // массив сессионных ключей зашифрования

for (int i = 0; i < 32; i++)  // заполняем массив сессионых ключей зашифрования
{
    if (i < 8) enc_session_key[i] = key[i];
    if ((i > 7) & (i < 16)) enc_session_key[i] = key[i - 8];
    if ((i > 15) & (i < 24)) enc_session_key[i] = key[i - 16];
    if ((i > 23) & (i < 32)) enc_session_key[i] = key[31 - i];
}

for (int i = 0; i < 32; i++)  // заполняем массив сессионых ключей расшифрования
{
    if (i < 8) dec_session_key[i] = key[i];
    if ((i > 7) & (i < 16)) dec_session_key[i] = key[15 - i];
    if ((i > 15) & (i < 24)) dec_session_key[i] = key[23 - i];
    if ((i > 23) & (i < 32)) dec_session_key[i] = key[31 - i];
}

ulong[] message_ulong; // массив из блоков по 64 бит исходного сообщения
ulong[] cipher_ulong; // массив из блоков по 64 бит зашифрованного сообщения

if (encrypt) // Если нужно зашифровать
{
    message_ulong = cs.read_from_file(message_file);  // берем файл исходного сообщения и читаем поблочно 64 бит
    Console.WriteLine("Исходное 64 разрядное сообщение");
    for (int i = 0; i < message_ulong.Length; i++) { Console.WriteLine(message_ulong[i]); } // выводим на экран
    Console.WriteLine();
    cipher_ulong = new ulong[message_ulong.Length];  // массив из блоков по 64 бит для зашифрованного сообщения
    for (int i = 0; i < message_ulong.Length; i++) { cipher_ulong[i] = cs.crypt(message_ulong[i], enc_session_key); } // и шифруем поблочно 64 бит
    Console.WriteLine("Зашифрованное 64 разрядное сообщение");
    for (int i = 0; i < cipher_ulong.Length; i++) { Console.WriteLine(cipher_ulong[i]); } // выводим на экран
    byte[] bytes = cs.abyte_from_aulong(cipher_ulong);
    File.WriteAllBytes("control.dat", bytes);
    File.WriteAllBytes(cipher_file, bytes);
}
if (decrypt)
{
    cipher_ulong = cs.read_from_file(cipher_file);
    Console.WriteLine("Исходный 64 разрядный шифртекст");
    for (int i = 0; i < cipher_ulong.Length; i++) { Console.WriteLine(cipher_ulong[i]); } // выводим на экран
    Console.WriteLine();
    message_ulong = new ulong[cipher_ulong.Length];  // массив из блоков по 64 бит для расшифрованного сообщения
    for (int i = 0; i < cipher_ulong.Length; i++) { message_ulong[i] = cs.crypt(cipher_ulong[i], dec_session_key); } // расшифровываем шифртекст
    Console.WriteLine("Расшифрованное 64 разрядное сообщение");
    for (int i = 0; i < message_ulong.Length; i++) { Console.WriteLine(message_ulong[i]); } // выводим на экран
    byte[] bytes = cs.abyte_from_aulong(message_ulong);
    File.WriteAllBytes("control.txt", bytes);
}

