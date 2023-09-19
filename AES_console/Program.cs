using AES_console;
using System.Text;

var text = "Two One Nine Two Two";
var key = "Thats my Kung Fu"; //LEN = 16

//WithInfoInConsole();

CleanUp();

void CleanUp()
{
    var aes = new AES128();

    var encryptedText = aes.Encrypt(text, key);

    Console.WriteLine($"Text: {text}");
    Console.WriteLine($"Key: {key}");

    Console.WriteLine("\nEncrypted bytes");
    foreach (var t in encryptedText)
        Console.Write($"{t:X2} ");

    var decrypted = aes.Decrypt(encryptedText, key);

    Console.WriteLine("\n\nDecrypted bytes");
    foreach (var t in decrypted)
        Console.Write($"{t:X2} ");

    Console.WriteLine($"\nDecrypted text: {Encoding.ASCII.GetString(decrypted)}");
}

void WithInfoInConsole()
{
    var aes = new AES_showcase();

    Console.ForegroundColor = ConsoleColor.Green;

    var encryptedText = aes.Encrypt(text, key);

    Console.WriteLine("\nEncrypted bytes");
    foreach (var t in encryptedText)
        Console.Write($"{t:X2} ");

    Console.ForegroundColor = ConsoleColor.Red;

    var decrypted = aes.Decrypt(encryptedText, key);

    Console.WriteLine("\nDecrypted bytes");
    foreach (var t in decrypted)
        Console.Write($"{t:X2} ");

    Console.WriteLine($"\nDecrypted text: {Encoding.ASCII.GetString(decrypted)}");
}