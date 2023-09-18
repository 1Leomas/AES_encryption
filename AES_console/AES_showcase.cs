using System.Collections;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace AES_console;
    
internal class AES_showcase
{
    private const int BLOCK_SIZE = 16;
    private const int KEY_SIZE = 128 / 8;
    private const int ROUNDS = 10;

    public byte[] Encrypt(string text, string key)  
    {
        int encryptedDataLen;
        if (text.Length % BLOCK_SIZE == 0)
            encryptedDataLen = text.Length;
        else
            encryptedDataLen = text.Length + BLOCK_SIZE - text.Length % BLOCK_SIZE;

        var encryptedData = new byte[encryptedDataLen];

        // transformam caracterele intr-un hex array
        byte[] inputInBytes = Encoding.UTF8.GetBytes(text);

        byte[] Key = Encoding.UTF8.GetBytes(key);
        if (Key.Length != KEY_SIZE)
            throw new Exception("Key must be 128 bits long");

        EncryptionConsoleInfo(text, key, inputInBytes, Key);

        // for 128 bytes need 10 + 1 keys
        // every Key are 16 bytes => 178 bytes
        var roundKeys = new byte[ROUNDS + 1][];

        // generate RoundKeys 
        KeyExpansion(Key, roundKeys);
        
        // luam a cate 16 caractere si le criptam
        for (int i = 0; i < inputInBytes.Length; i += BLOCK_SIZE)
        {
            Console.WriteLine($"\n\n---------------- Text Block {(i+2)/16} ----------------\n");

            int endIndex = Math.Min(i + BLOCK_SIZE, inputInBytes.Length);
            
            byte[] block = new byte[BLOCK_SIZE];

            Array.Copy(inputInBytes, i, block, 0, endIndex - i);

            //transformam in matrice 4x4
            byte[,] stateArray = new byte[4, 4];
            GetStateArray(block, stateArray);

            //print state at console
            PrintMatrix(stateArray, "\nInitial State Array");
            
            AddRoundKey(stateArray, roundKeys[0]);

            //print state at console
            PrintMatrix(stateArray, "After AddRoundKey");

            // Primele 9 runde
            for (var j = 0; j < ROUNDS - 1; j++)
            {
                Console.WriteLine($"\n\n----------- ROUND {j+1} -----------\n");

                SubBytes(stateArray);
                PrintMatrix(stateArray, "After SubBytes");

                ShiftRows(stateArray);
                PrintMatrix(stateArray, "After ShiftRows");

                MixColumn(stateArray);
                PrintMatrix(stateArray, "After MixColumn");

                AddRoundKey(stateArray, roundKeys[j+1]);
                PrintMatrix(stateArray, "After AddRoundKey");
            }

            // Ultima runda
            Console.WriteLine($"\n\n----------- ROUND {10} -----------\n");

            SubBytes(stateArray);
            PrintMatrix(stateArray, "After SubBytes");

            ShiftRows(stateArray);
            PrintMatrix(stateArray, "After ShiftRows");

            AddRoundKey(stateArray, roundKeys[ROUNDS]);
            PrintMatrix(stateArray, "After AddRoundKey");

            for (int k = 0; k < 4; k++)
                for (int l = 0; l < 4; l++)
                    encryptedData[k * 4 + l + i] = stateArray[l, k];
        }

        return encryptedData;
    }

    /// <summary>
    /// Generate ROUNDS + 1 keys
    /// </summary>
    /// <param name="key"></param>
    private void KeyExpansion(byte[] key, byte[][] roundKeys)
    {
        // declaram cheile
        for (int i = 0; i < ROUNDS + 1; ++i)
            roundKeys[i] = new byte[KEY_SIZE];

        // save first 16 bytes from Key in first roundKey
        Array.Copy(key, roundKeys[0], KEY_SIZE);

        for (int i = 0; i < 10; i++)
        {
            Array.Copy(roundKeys[i], roundKeys[i + 1], KEY_SIZE);

            byte[] word = new byte[4];

            // copy last column of previous round key
            Array.Copy(roundKeys[i], 12, word, 0, 4);

            RotWord(word);

            SubWord(word);

            word[0] ^= LookupTables.RCON[i+1];

            // XOR cu ultima coloana din runda precedenta
            for (int j = 0; j < 4; j++)
                roundKeys[i + 1][j] = (byte)(roundKeys[i][j] ^ word[j]);

            for (int j = 0; j < KEY_SIZE - 4; ++j)
                roundKeys[i + 1][j + 4] = (byte)(roundKeys[i + 1][j] ^ roundKeys[i][j + 4]);
        }
        
    }


    /// <summary>
    /// Take as input a value of 4 bytes
    /// Return as output a rotation of these 4 bytes
    /// </summary>
    /// <param name="word"></param>
    private void RotWord(byte[] word)
    {
        (word[0], word[1], word[2], word[3]) 
                        = 
        (word[1], word[2], word[3], word[0]);
    }

    private void SubWord(byte[] word)
    {
        word[0] = LookupTables.SBOX[word[0]];
        word[1] = LookupTables.SBOX[word[1]];
        word[2] = LookupTables.SBOX[word[2]];
        word[3] = LookupTables.SBOX[word[3]];
    }

    private void GetStateArray(byte[] data, byte[,] stateArray)
    {
        var inputBytesLen = data.Length;

        for (var i = 0; i < 4; i++)
        {
            for(var j = 0; j < 4; j++)
            {
                if(i*4+j == inputBytesLen)
                    return;

                // matricea se formeaza pe coloane
                stateArray[i,j] = data[j * 4 + i];
            }
        }
    }
            
    public byte[] Decrypt(byte[] dataBytes, string key)
    {
        var decryptedData = new byte[dataBytes.Length];

        byte[] Key = Encoding.UTF8.GetBytes(key);

        if (Key.Length != KEY_SIZE)
            throw new Exception("Key must be 128 bits long");

        DecryptionConsoleInfo(dataBytes, key, Key);

        // for 128 bytes need 10 + 1 keys
        // every Key are 16 bytes => 178 bytes
        var roundKeys = new byte[ROUNDS + 1][];

        // generate RoundKeys 
        KeyExpansion(Key, roundKeys);

        // luam a cate 16 caractere si le decriptam
        // blocurile sunt independente asa ca nu are importanta ordinea
        for (int i = 0; i < dataBytes.Length; i += BLOCK_SIZE)
        {
            Console.WriteLine($"\n\n---------------- Text Block {(i / 16) + 1} ----------------\n");

            int endIndex = Math.Min(i + BLOCK_SIZE, dataBytes.Length);

            byte[] block = new byte[BLOCK_SIZE];

            Array.Copy(dataBytes, i, block, 0, endIndex - i);

            //transformam in matrice 4x4
            byte[,] stateArray = new byte[4, 4];
            GetStateArray(block, stateArray);

            PrintMatrix(stateArray, "\nState before decryption");

            Console.WriteLine($"\n\n----------- ROUND 10 -----------\n");
            
            AddRoundKey(stateArray, roundKeys[ROUNDS]);
            PrintMatrix(stateArray, "After add round key");

            InvShiftRows(stateArray);
            PrintMatrix(stateArray, $"After InvShiftRows");

            InvSubBytes(stateArray);
            PrintMatrix(stateArray, $"After InvSubBytes");

            // Primele 9 runde
            for (int j = ROUNDS - 1; j > 0; j--)
            {
                Console.WriteLine($"\n\n----------- ROUND {j} -----------\n");

                AddRoundKey(stateArray, roundKeys[j]);
                PrintMatrix(stateArray, "After add round key");

                InvMixColumn(stateArray);
                PrintMatrix(stateArray, $"After InvMixColumn");

                InvShiftRows(stateArray);
                PrintMatrix(stateArray, $"After InvShiftRows");

                InvSubBytes(stateArray);
                PrintMatrix(stateArray, $"After InvSubBytes");
            }

            Console.WriteLine($"\n\n----------- ROUND 0 -----------\n");
            AddRoundKey(stateArray, roundKeys[0]);
            PrintMatrix(stateArray, "After add round key");

            //add state to byte array
            for (int k = 0; k < 4; k++)
                for (int l = 0; l < 4; l++)
                    decryptedData[k * 4 + l + i] = stateArray[l, k];
        }

        return decryptedData;
    }

    private void AddRoundKey(byte[,] stateArray, byte[] roundKey)
    {
        // XOR cu roundKey
        for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            stateArray[i, j] ^= roundKey[j * 4 + i];
    }

    private void MixColumn(byte[,] stateArray)
    {
        byte[,] temp = new byte[4, 4];

        for (int i = 0; i < 4; i++)
        {
            temp[0, i] = (byte)(LookupTables.M2[stateArray[0, i]] ^ LookupTables.M3[stateArray[1, i]] ^ stateArray[2, i] ^ stateArray[3, i]);
            temp[1, i] = (byte)(stateArray[0, i] ^ LookupTables.M2[stateArray[1, i]] ^ LookupTables.M3[stateArray[2, i]] ^ stateArray[3, i]);
            temp[2, i] = (byte)(stateArray[0, i] ^ stateArray[1, i] ^ LookupTables.M2[stateArray[2, i]] ^ LookupTables.M3[stateArray[3, i]]);
            temp[3, i] = (byte)(LookupTables.M3[stateArray[0, i]] ^ stateArray[1, i] ^ stateArray[2, i] ^ LookupTables.M2[stateArray[3, i]]);
        }

        Array.Copy(temp, stateArray, 16);

    }

    private void InvMixColumn(byte[,] stateArray)
    {
        byte[,] temp = new byte[4, 4];

        for (int i = 0; i < 4; i++)
        {
            temp[0, i] = (byte)(LookupTables.M14[stateArray[0, i]] ^ LookupTables.M11[stateArray[1, i]] ^ LookupTables.M13[stateArray[2, i]] ^ LookupTables.M9[stateArray[3, i]]);
            temp[1, i] = (byte)(LookupTables.M9[stateArray[0, i]] ^ LookupTables.M14[stateArray[1, i]] ^ LookupTables.M11[stateArray[2, i]] ^ LookupTables.M13[stateArray[3, i]]);
            temp[2, i] = (byte)(LookupTables.M13[stateArray[0, i]] ^ LookupTables.M9[stateArray[1, i]] ^ LookupTables.M14[stateArray[2, i]] ^ LookupTables.M11[stateArray[3, i]]);
            temp[3, i] = (byte)(LookupTables.M11[stateArray[0, i]] ^ LookupTables.M13[stateArray[1, i]] ^ LookupTables.M9[stateArray[2, i]] ^ LookupTables.M14[stateArray[3, i]]);
        }

        Array.Copy(temp, stateArray, 16);
    }

    //takes a byte and returns a corresponding byte according to a look-up table
    private void SubBytes(byte[,] stateArray)
    {
        for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            stateArray[i, j] = LookupTables.SBOX[stateArray[i, j]];
    }

    private void InvSubBytes(byte[,] stateArray)
    {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                stateArray[i, j] = LookupTables.ISBOX[stateArray[i, j]];
    }

    private void ShiftRows(byte[,] stateArray)
    {
        // shift row 1 with 1 position left
        (stateArray[1, 0], stateArray[1, 1], stateArray[1, 2], stateArray[1, 3]) =
        (stateArray[1, 1], stateArray[1, 2], stateArray[1, 3], stateArray[1, 0]);

        // shift row 2 with 2 position left
        (stateArray[2, 0], stateArray[2, 1], stateArray[2, 2], stateArray[2, 3]) =
        (stateArray[2, 2], stateArray[2, 3], stateArray[2, 0], stateArray[2, 1]);

        // shift row 3 with 3 position left
        (stateArray[3, 0], stateArray[3, 1], stateArray[3, 2], stateArray[3, 3]) =
        (stateArray[3, 3], stateArray[3, 0], stateArray[3, 1], stateArray[3, 2]);
    }

    private void InvShiftRows(byte[,] stateArray)
    {
        // shift row 1 with 1 position right
        (stateArray[1, 0], stateArray[1, 1], stateArray[1, 2], stateArray[1, 3]) =
        (stateArray[1, 3], stateArray[1, 0], stateArray[1, 1], stateArray[1, 2]);
        // shift row 2 with 2 position right
        (stateArray[2, 0], stateArray[2, 1], stateArray[2, 2], stateArray[2, 3]) =
        (stateArray[2, 2], stateArray[2, 3], stateArray[2, 0], stateArray[2, 1]);
        // shift row 3 with 3 position right
        (stateArray[3, 0], stateArray[3, 1], stateArray[3, 2], stateArray[3, 3]) =
        (stateArray[3, 1], stateArray[3, 2], stateArray[3, 3], stateArray[3, 0]);
    }

    private static void EncryptionConsoleInfo(string text, string key, byte[] inputInBytes, byte[] Key)
    {
        Console.WriteLine("ENCRYPTION\n\n");
        Console.WriteLine($"Input text: {text}");
        Console.Write("Input text in hex: ");
        for (int i = 0; i < inputInBytes.Length; i++)
        {
            Console.Write(inputInBytes[i].ToString("X") + " ");
        }

        Console.WriteLine($"\n\nKey: {key}");
        Console.Write("Key in hex: ");
        for (int i = 0; i < Key.Length; i++)
        {
            Console.Write(Key[i].ToString("X") + " ");
        }

        Console.WriteLine();
    }
    private static void DecryptionConsoleInfo(byte[] dataBytes, string key, byte[] Key)
    {
        Console.WriteLine("\n\nDECRYPTION\n\n");
        Console.Write("Input in hex: ");
        for (int i = 0; i < dataBytes.Length; i++)
        {
            Console.Write(dataBytes[i].ToString("X") + " ");
        }

        Console.WriteLine($"\n\nKey: {key}");
        Console.Write("Key in hex: ");
        for (int i = 0; i < Key.Length; i++)
        {
            Console.Write(Key[i].ToString("X") + " ");
        }

        Console.WriteLine();
    }

    void PrintMatrix(byte[,] matrix, string name = "")
    {
        Console.WriteLine(name);
        // print state at console
        for (int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                Console.Write(matrix[j, k].ToString("X2") + " ");
            }
            Console.WriteLine();
        }

        Console.WriteLine();
    }
}