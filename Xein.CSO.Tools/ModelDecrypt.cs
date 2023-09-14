using System.Security.Cryptography;

namespace Xein.CSO.Tools;

internal sealed class IceCryptoTransform : ICryptoTransform
{
    internal IceCryptoTransform(int n, byte[] key, bool encrypt)
    {
        this.encrypt = encrypt;
        InitializeSBox();
        if (n == 0)
        {
            size   = 1;
            rounds = 8;
        }
        else
        {
            size   = n;
            rounds = n << 4;
        }
        keySchedule = new uint[rounds, 3];
        SetKey(key);
    }

    private static uint GFMultiply(uint a, uint b, uint m)
    {
        var res = 0U;
        while (b != 0U)
        {
            if ((b & 1U) != 0U)
                res ^= a;
            a <<= 1;
            b >>= 1;
            if (a >= 256U)
                a ^= m;
        }
        return res;
    }

    private static uint GFExp7(uint b, uint m)
    {
        if (b == 0U)
            return 0U;
        var x = GFMultiply(b, b, m);
        x = GFMultiply(b, x, m);
        x = GFMultiply(x, x, m);
        return GFMultiply(b, x, m);
    }

    private static uint Perm32(uint x)
    {
        var res  = 0U;
        var pbox = 0;
        while (x != 0U)
        {
            if ((x & 1U) != 0U)
                res |= PBox[pbox];
            pbox++;
            x >>= 1;
        }
        return res;
    }

    private static void InitializeSBox()
    {
        SBox = new uint[4, 1024];
        for (var i = 0; i < 1024; i++)
        {
            var col = i                                                                >> 1 & 255;
            var row = (i & 1) | (i & 512)                                              >> 8;
            SBox[0, i] = Perm32(GFExp7((uint)(col ^ SXor[0, row]), (uint)SMod[0, row]) << 24);
            SBox[1, i] = Perm32(GFExp7((uint)(col ^ SXor[1, row]), (uint)SMod[1, row]) << 16);
            SBox[2, i] = Perm32(GFExp7((uint)(col ^ SXor[2, row]), (uint)SMod[2, row]) << 8);
            SBox[3, i] = Perm32(GFExp7((uint)(col ^ SXor[3, row]), (uint)SMod[3, row]));
        }
    }

    private void BuildSchedule(ushort[] keyBuilder, int n, int keyRotationOffset)
    {
        for (var i = 0; i < 8; i++)
        {
            var keyRotation = KeyRotation[keyRotationOffset + i];
            var subKeyIndex = n + i;
            keySchedule[subKeyIndex, 0] = 0U;
            keySchedule[subKeyIndex, 1] = 0U;
            keySchedule[subKeyIndex, 2] = 0U;
            for (var j = 0; j < 15; j++)
            {
                for (var k = 0; k < 4; k++)
                {
                    var currentKeyBuilder = keyBuilder[keyRotation + k & 3];
                    var bit               = (ushort)(currentKeyBuilder & 1);
                    keySchedule[subKeyIndex, j % 3] = (keySchedule[subKeyIndex, j % 3] << 1 | bit);
                    keyBuilder[keyRotation + k & 3] = (ushort)(currentKeyBuilder >> 1 | (bit ^ 1) << 15);
                }
            }
        }
    }

    private void SetKey(byte[] key)
    {
        var keyBuilder = new ushort[4];
        if (rounds == 8)
        {
            if (key.Length != 8)
                throw new ArgumentException("Key size is not valid.", nameof(key));
            for (var i = 0; i < 4; i++)
                keyBuilder[3 - i] = (ushort)(key[i << 1] << 8 | key[(i << 1) + 1]);
            BuildSchedule(keyBuilder, 0, 0);
        }
        else
        {
            if (key.Length != size << 3)
                throw new ArgumentException("Key size is not valid.", nameof(key));
            for (var i = 0; i < size; i++)
            {
                var pos = i << 3;
                for (var j = 0; j < 4; j++)
                    keyBuilder[3 - j] = (ushort)(key[pos + (j << 1)] << 8 | key[pos + (j << 1) + 1]);
                BuildSchedule(keyBuilder, pos,                   0);
                BuildSchedule(keyBuilder, rounds - 8 - pos, 8);
            }
        }
    }

    private uint Transform(uint value, int subKeyIndex)
    {
        var tl = (value >> 16 & 1023U) | ((value >> 14 | value << 18) & 1047552U);
        var tr = (value       & 1023U) | (value << 2                  & 1047552U);
        var al = keySchedule[subKeyIndex, 2] & (tl ^ tr);
        var ar = al ^ tr;
        al ^= tl;
        al ^= keySchedule[subKeyIndex, 0];
        ar ^= keySchedule[subKeyIndex, 1];

        return SBox[0, (int)(al >> 10)]   |
               SBox[1, (int)(al & 1023U)] |
               SBox[2, (int)(ar >> 10)]   |
               SBox[3, (int)(ar & 1023U)];
    }

    private void Encrypt(byte[] input, int inputOffset, byte[] output, int outputOffset)
    {
        var i = (uint)(input[inputOffset] << 24 | input[inputOffset + 1] << 16 | input[inputOffset + 2] << 8  | input[inputOffset                               + 3]);
        var r = (uint)(input[inputOffset                            + 4] << 24 | input[inputOffset + 5] << 16 | input[inputOffset + 6] << 8 | input[inputOffset + 7]);
        for (var j = 0; j < rounds; j += 2)
        {
            i ^= Transform(r, j);
            r ^= Transform(i, j + 1);
        }
        output[outputOffset]     = (byte)(r >> 24 & 255U);
        output[outputOffset + 1] = (byte)(r >> 16 & 255U);
        output[outputOffset + 2] = (byte)(r >> 8  & 255U);
        output[outputOffset + 3] = (byte)(r       & 255U);
        output[outputOffset + 4] = (byte)(i >> 24 & 255U);
        output[outputOffset + 5] = (byte)(i >> 16 & 255U);
        output[outputOffset + 6] = (byte)(i >> 8  & 255U);
        output[outputOffset + 7] = (byte)(i       & 255U);
    }

    private void Decrypt(byte[] input, int inputOffset, byte[] output, int outputOffset)
    {
        var i = (uint)(input[inputOffset] << 24 | input[inputOffset + 1] << 16 | input[inputOffset + 2] << 8  | input[inputOffset                               + 3]);
        var r = (uint)(input[inputOffset                            + 4] << 24 | input[inputOffset + 5] << 16 | input[inputOffset + 6] << 8 | input[inputOffset + 7]);
        for (var j = rounds - 1; j > 0; j -= 2)
        {
            i ^= Transform(r, j);
            r ^= Transform(i, j - 1);
        }
        output[outputOffset]     = (byte)(r >> 24 & 255U);
        output[outputOffset + 1] = (byte)(r >> 16 & 255U);
        output[outputOffset + 2] = (byte)(r >> 8  & 255U);
        output[outputOffset + 3] = (byte)(r       & 255U);
        output[outputOffset + 4] = (byte)(i >> 24 & 255U);
        output[outputOffset + 5] = (byte)(i >> 16 & 255U);
        output[outputOffset + 6] = (byte)(i >> 8  & 255U);
        output[outputOffset + 7] = (byte)(i       & 255U);
    }

    public bool CanReuseTransform          => false;
    public bool CanTransformMultipleBlocks => true;
    public int  InputBlockSize             => 8;
    public int  OutputBlockSize            => 8;

    public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
    {
        if (inputBuffer == null)
            throw new ArgumentNullException(nameof(inputBuffer));
        if (inputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(inputOffset));
        if (inputOffset + inputCount > inputBuffer.Length)
            throw new ArgumentOutOfRangeException(nameof(inputCount));
        if (outputBuffer == null)
            throw new ArgumentNullException(nameof(outputBuffer));
        if (outputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(outputOffset));
        if (outputOffset + inputCount > outputBuffer.Length)
            throw new ArgumentOutOfRangeException(nameof(inputCount));

        if (encrypt)
        {
            for (var i = 0; i < inputCount; i += 8)
            {
                Encrypt(inputBuffer, inputOffset, outputBuffer, outputOffset);
                inputOffset  += 8;
                outputOffset += 8;
            }
        }
        else
        {
            for (var i = 0; i < inputCount; i += 8)
            {
                Decrypt(inputBuffer, inputOffset, outputBuffer, outputOffset);
                inputOffset  += 8;
                outputOffset += 8;
            }
        }

        return inputCount;
    }

    public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
    {
        if (inputBuffer == null)
            throw new ArgumentNullException(nameof(inputBuffer));
        if (inputOffset < 0)
            throw new ArgumentOutOfRangeException(nameof(inputOffset));
        if (inputOffset + inputCount > inputBuffer.Length)
            throw new ArgumentOutOfRangeException(nameof(inputCount));

        var outputBuffer = new byte[inputCount + 7 & -8];
        var outputOffset = 0;
        
        if (encrypt)
        {
            for (var i = 0; i < inputCount; i += 8)
            {
                Encrypt(inputBuffer, inputOffset, outputBuffer, outputOffset);
                inputOffset  += 8;
                outputOffset += 8;
            }
        }
        else
        {
            for (var i = 0; i < inputCount; i += 8)
            {
                Decrypt(inputBuffer, inputOffset, outputBuffer, outputOffset);
                inputOffset  += 8;
                outputOffset += 8;
            }
        }

        return outputBuffer;
    }

    public void Dispose()
    {
        size   = 0;
        rounds = 0;
        for (var i = 0; i < keySchedule.GetLength(0); i++)
            for (var j = 0; j < keySchedule.GetLength(1); j++)
                keySchedule[i, j] = 0U;
        keySchedule = new uint[0, 0];
    }

    private static          uint[,] SBox;
    private static readonly int[]   KeyRotation = new int[] { 0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2, };
    private readonly        bool    encrypt;
    private                 int     size;
    private                 int     rounds;
    private                 uint[,] keySchedule;
    
    private static readonly int[,] SMod = new int[,] { { 333, 313, 505, 369, },
                                                       { 379, 375, 319, 391, },
                                                       { 361, 445, 451, 397, },
                                                       { 397, 425, 395, 505, }, };
    private static readonly int[,] SXor = new int[,] { { 131, 133, 155, 205, },
                                                       { 204, 167, 173, 65, },
                                                       { 75, 46, 212, 51, },
                                                       { 234, 203, 46, 4, }, };
    private static readonly uint[] PBox = new uint[] { 1U, 128U, 1024U, 8192U, 524288U, 2097152U, 16777216U, 1073741824U,
                                                       8U, 32U, 256U, 16384U, 65536U, 8388608U, 67108864U, 536870912U,
                                                       4U, 16U, 512U, 32768U, 131072U, 4194304U, 134217728U, 268435456U,
                                                       2U, 64U, 2048U, 4096U, 262144U, 1048576U, 33554432U, 2147483648U, };
}

public sealed class Ice : SymmetricAlgorithm
{
    public Ice() : this(0) { }

    public Ice(int n)
    {
        if (n < 0)
            throw new ArgumentOutOfRangeException(nameof(n));

        this.n               = n;
        ModeValue            = CipherMode.ECB;
        PaddingValue         = PaddingMode.None;
        BlockSizeValue       = 64;
        LegalBlockSizesValue = new KeySizes[] { new(BlockSizeValue, BlockSizeValue, 0), };
        KeySizeValue         = Math.Max(n << 6, 64);
        LegalKeySizesValue   = new KeySizes[] { new(KeySizeValue, KeySizeValue, 0), };
    }

    public override CipherMode Mode
    {
        get => base.Mode;
        set
        {
            if (value != CipherMode.ECB)
                throw new NotSupportedException("Only ECB is currently supported.");
            base.Mode = value;
        }
    }

    public override PaddingMode Padding
    {
        get => base.Padding;
        set
        {
            if (value != PaddingMode.None)
                throw new NotSupportedException("No padding is currently supported.");

            base.Padding = value;
        }
    }

    public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
    {
        if (rgbKey == null)
            throw new ArgumentNullException(nameof(rgbKey));
        if (rgbKey.Length != KeySizeValue >> 3)
            throw new ArgumentException("Key size is not valid.", nameof(rgbKey));

        return new IceCryptoTransform(n, rgbKey, false);
    }

    public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
    {
        if (rgbKey == null)
            throw new ArgumentNullException(nameof(rgbKey));
        if (rgbKey.Length != KeySizeValue >> 3)
            throw new ArgumentException("Key size is not valid.", nameof(rgbKey));

        return new IceCryptoTransform(n, rgbKey, true);
    }

    public override void GenerateIV()
    {
        var rng = RandomNumberGenerator.Create();
        var iv  = new byte[8];
        rng.GetBytes(iv);
        IVValue = iv;
    }

    public override void GenerateKey()
    {
        var rng = RandomNumberGenerator.Create();
        var key = new byte[KeySizeValue >> 3];
        rng.GetBytes(key);
        KeyValue = key;
    }

    private int n;
}
