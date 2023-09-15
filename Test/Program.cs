


byte[] word = new byte[4];

// insert some data in the word array for testing RotWord function
word[0] = 0x20;
word[1] = 0x76;
word[2] = 0x75;
word[3] = 0x67;

RotWord(word);

Console.ReadLine();


        
void RotWord(byte[] word)
{
    (word[0], word[1], word[2], word[3]) =
        (word[1], word[2], word[3], word[0]);
}