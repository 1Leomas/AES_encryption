using AES_console;
using System.Text;
//using static System.Runtime.Intrinsics.X86.Aes;
//using static System.Runtime.Intrinsics.X86.Sse2;

var text = "Two One Nine Two Two";
var key = "Thats my Kung Fu";

var aes = new AesEncrypt();

var encryptedText = aes.Encrypt(text, key);

Console.WriteLine("\nCiphertext");
for (int i = 0; i < encryptedText.Length; i++)
    Console.Write($"{encryptedText[i]:X2} ");


var decrypted = aes.Decrypt(encryptedText, key);
 
Console.WriteLine("\nDecrypted");
for (int i = 0; i < decrypted.Length; i++)
    Console.Write($"{decrypted[i]:X2} ");

Console.WriteLine($"\nDecrypted text: {Encoding.ASCII.GetString(decrypted)}");

Console.ReadLine();