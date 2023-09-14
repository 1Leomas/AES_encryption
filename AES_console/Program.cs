using AES_console;
using System.Text;
//using static System.Runtime.Intrinsics.X86.Aes;
//using static System.Runtime.Intrinsics.X86.Sse2;


var aes = new AesEncrypt();

aes.Encrypt();




Console.ReadLine();





void TestAes128()
{
    var data = Encoding.ASCII.GetBytes("Zboara departe");

    var key = Encoding.UTF8.GetBytes("1234567891234567");

    var aes128 = new AES128(key);

    byte[] crypted = new byte[128];


    aes128.Encrypt(data, ref crypted);

    var cstr = Convert.ToBase64String(crypted);

    var s = Encoding.UTF8.GetString(aes128.Key);

    var decriptedBytes = new byte[128];

    aes128.Decrypt(crypted, ref decriptedBytes);

    var decText = Encoding.UTF8.GetString(decriptedBytes);
}