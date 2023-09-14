using System.Runtime.InteropServices;
using System.Text;

namespace Xein.CSO.Tools;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct PakHeader
{
    public const string PAK_KEY                = "CqeLFV@*0IfewH";
    public const byte   PAK_VERSION            = 2;
    public const uint   PAK_ENTRY_MAX_PATH_LEN = 0x4000;
    public const int    PAK_TYPE_TOP_BYTES     = 0x400;
    
    public                                                      uint   iChecksum;
    public                                                      byte   iVersion;
    public                                                      uint   iEntries;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] public byte[] pad;

    public bool IsValid()
    {
        return iVersion == PAK_VERSION && iVersion + iEntries == iChecksum;
    }
}

public enum PakFileType
{
    PAK_UNCOMPRESSED = 0x0,
    PAK_COMPRESSED = 0x1,
    PAK_ENCRYPTED = 0x2,
    PAK_ENCRYPTED_AGAIN = 0x4,
}

public struct PakEntry
{
    public                                                      string      szFilePath;
    public                                                      uint        iUnk;
    public                                                      PakFileType iType;
    public                                                      uint        iOffset;
    public                                                      uint        iSizeOriginal;
    public                                                      uint        iSizePacked;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[]      iKey;

    private byte[] GenerateDataKey()
    {
        var res = new byte[128];
        for (var i = 0; i < res.Length; i++)
        {
            uint charValue = szFilePath[i % szFilePath.Length];
            uint keyByte   = iKey[i  % 16];
            res[i] = (byte)(i + charValue * (i + keyByte - 5 * ((((0x66666667 * i) >> 32) >> 1) + (((0x66666667 * i) >> 32) >> 31)) + 2));
        }
        return res;
    }

    public (bool, byte[]) Unpack(PakFile pak)
    {
        var finalBuffer = new byte[iSizeOriginal];

        var dataKey     = GenerateDataKey();
        var startOffset = Convert.ToInt32(pak.iOffsetData + (iOffset << 10));

        if (iType is PakFileType.PAK_ENCRYPTED_AGAIN)
        {
            PakView view = new(pak.szBackupBuffer[startOffset..^startOffset], dataKey);
            var     buf  = view.ReadBytes(Convert.ToInt32(iSizeOriginal), true);

            Array.Copy(buf, finalBuffer, buf.Length);
        }

        if (iType is PakFileType.PAK_ENCRYPTED)
        {
            var     maxTopBytes = Math.Min(PakView.GetAlignedLength(finalBuffer.Length), PakHeader.PAK_TYPE_TOP_BYTES);
            PakView view        = new(finalBuffer, dataKey);
            var     buf         = view.ReadBytes(maxTopBytes, true);

            Array.Copy(buf, finalBuffer, buf.Length);
        }

        if (iType is PakFileType.PAK_COMPRESSED)
        {
            throw new NotImplementedException("IMPLEMENT ME");
        }

        return (true, finalBuffer);
    }
}

public class PakView
{
    private SnowCipher pCipher = new();
    private byte[]     szBuffer;
    private int        iOffsetCur;
    private byte[]     szAvailableBytes;
    private int        iAvailableBytesCount;

    public PakView(byte[] buffer, byte[] key)
    {
        szBuffer             = buffer;
        iOffsetCur           = 0;
        iAvailableBytesCount = 0;
        
        pCipher.SetKey(key);
    }

    public static int GetAlignedLength(int len)
    {
        return 4 * ((len + 4 - 1) / 4);
    }

    public uint Read()
    {
        var arr = new byte[4];
        
        var  byteLen    = sizeof(uint);
        var  alignedLen = GetAlignedLength(byteLen);

        if (iAvailableBytesCount > 0)
        {
            ReadRemainingData(arr);
        }
        else
        {
            var buf = ReadBytes(alignedLen);
            Array.Copy(buf, arr, byteLen);
            SaveAnyRemainingBytes(arr, byteLen, alignedLen);
        }

        return BitConverter.ToUInt32(arr);
    }

    public string ReadString(int size)
    {
        var byteLen    = size * 2; // u16string
        var alignedLen = GetAlignedLength(byteLen);

        var strArr = new byte[byteLen];

        if (iAvailableBytesCount > 0)
        {
            ReadRemainingData(strArr);
        }
        else
        {
            if (!CanReadBytes(alignedLen))
                throw new IndexOutOfRangeException("The data buffer is too small");

            var buf = ReadBytes(alignedLen);
            Array.Copy(buf, strArr, byteLen);
            SaveAnyRemainingBytes(strArr, byteLen, alignedLen);
        }

        return Encoding.Unicode.GetString(strArr);
    }

    public uint[] ReadArray()
    {
        var byteLen    = sizeof(uint) * 4;
        var alignedLen = GetAlignedLength(byteLen);

        var ret = new byte[byteLen];

        if (iAvailableBytesCount > 0)
        {
            ReadRemainingData(ret);
        }
        else
        {
            if (!CanReadBytes(alignedLen))
                throw new IndexOutOfRangeException("The array length is larger than available data");

            var buf = ReadBytes(alignedLen);
            Array.Copy(buf, ret, byteLen);
            SaveAnyRemainingBytes(ret, byteLen, alignedLen);
        }

        return new[] {
                     BitConverter.ToUInt32(ret, 0),
                     BitConverter.ToUInt32(ret, 4),
                     BitConverter.ToUInt32(ret, 8),
                     BitConverter.ToUInt32(ret, 12), };
    }
    
    public byte[] ReadBytes(int length, bool aligned = false)
    {
        if (aligned)
            length = GetAlignedLength(length);

        if (!CanReadBytes(length))
            throw new IndexOutOfRangeException("The data buffer is too small");

        var ret = new byte[length];
        pCipher.DecryptBuffer(ret, szBuffer, length);
        return ret;
    }

    public int GetCurOffset() => iOffsetCur;

    private void SaveAnyRemainingBytes(byte[] buf, int len, int alignedLen)
    {
        var leftover = alignedLen - len;
        if (leftover > 0)
        {
            Array.Copy(buf, len, szAvailableBytes, iAvailableBytesCount, leftover);
            iAvailableBytesCount += leftover;
        }
    }

    private void ReadRemainingData(byte[] data)
    {
        Buffer.BlockCopy(szAvailableBytes.ToArray(), 0, data.ToArray(), 0, iAvailableBytesCount);

        if (iAvailableBytesCount >= data.Length)
        {
            iAvailableBytesCount -= data.Length;
        }
        else
        {
            var remainingBytes  = data.Length - iAvailableBytesCount;
            var alignedRemBytes = GetAlignedLength(remainingBytes);
            var offset          = iAvailableBytesCount;

            iAvailableBytesCount = 0;

            byte[] remainingBuf = ReadBytes(alignedRemBytes);

            SaveAnyRemainingBytes(remainingBuf, remainingBytes, alignedRemBytes);

            Buffer.BlockCopy(remainingBuf, 0, data.Skip(offset).ToArray(), 0, remainingBytes);
        }
    }
    
    public bool CanReadBytes(int bytes)
    {
        return szBuffer.Length >= iOffsetCur + bytes;
    }

    public int GetRemainingBytes()
    {
        return szBuffer.Length - iOffsetCur;
    }
}

public class PakFile
{
    public byte[] szBuffer;
    public byte[] szBackupBuffer;
    public string szFileName;

    public int iOffsetHeader;
    public int iOffsetEntries;
    public int iOffsetData;

    public PakHeader      header;
    public List<PakEntry> entries = new();
    
    public PakFile(byte[] buffer, string fileName)
    {
        Console.WriteLine($"PakFile: {fileName}");
        
        szFileName     = fileName;
        szBuffer       = buffer;
        szBackupBuffer = buffer;

        iOffsetHeader  = 0;
        iOffsetEntries = 0;
        iOffsetData    = 0;
    }

    public bool ParseHeader()
    {
        var key        = GenerateHeaderKey(szFileName);
        var sumOfChars = GetSumOfChars(szFileName);
        iOffsetHeader = sumOfChars % 312 + 30;
        var temp = szBuffer.Length - iOffsetHeader;
        header = GetPakHeader(szBuffer[new Range(iOffsetHeader, temp)] , key);
        return header.IsValid();
    }

    public bool ParseEntries()
    {
        var entriesKey = GenerateEntriesKey(szFileName);

        iOffsetEntries = iOffsetHeader + 42 + (GetSpecialSumOfChars(szFileName) % 212);

        PakView view = new(szBuffer[iOffsetEntries..^iOffsetEntries], entriesKey);

        for (var i = 0; i < header.iEntries; i++)
        {
            var strPathLen = view.Read();
            if (strPathLen > PakHeader.PAK_ENTRY_MAX_PATH_LEN)
                return false;

            var filePath = view.ReadString(Convert.ToInt32(strPathLen));
            var unk      = view.Read();
            var type     = view.Read();
            var offset   = view.Read();
            var realSize = view.Read();
            var packSize = view.Read();
            var baseKey  = view.ReadArray();

            entries.Add(new()
                        { szFilePath    = filePath,
                          iUnk          = unk,
                          iType         = (PakFileType)type,
                          iOffset       = offset,
                          iSizeOriginal = realSize,
                          iSizePacked   = packSize,
                          iKey          = baseKey, });
        }

        iOffsetData = iOffsetEntries + view.GetCurOffset();
        
        if ((iOffsetData & 0x3FF) != 0)
            iOffsetData = iOffsetData - (iOffsetData * 0x3FF) + 0x400;
        
        return true;
    }
    
    private static byte[] GenerateHeaderKey(string filename)
    {
        var res      = new byte[128];
        var fullKey  = filename + PakHeader.PAK_KEY;
        var keyBytes = Encoding.UTF8.GetBytes(fullKey);
        for (var i = 0; i < res.Length; i++)
            res[i] = (byte)(i + keyBytes[i % keyBytes.Length]);
        return res;
    }
    private static byte[] GenerateEntriesKey(string filename)
    {
        var res     = new byte[128];
        var fullKey = $"{filename}{PakHeader.PAK_KEY}";
        for (var i = 0; i < res.Length; i++)
            res[i] = (byte)(i + (i - 3 * (((0x55555556L * i) >> 32) + (((0x55555556L * i) >> 32) >> 31)) + 2) * fullKey[fullKey.Length - i % fullKey.Length - 1]);
        return res;
    }
    private static int GetSpecialSumOfChars(ReadOnlySpan<char> str)
    {
        var res = 0;
        foreach (var character in str)
            res += character + character * 2;
        return res;
    }

    private static int GetSumOfChars(string str)
    {
        var res = 0;
        foreach (var ch in str)
            res += ch;
        return res;
    }
    
    private PakHeader GetPakHeader(byte[] pkgData, byte[] key)
    {
        var snow = new SnowCipher();
        snow.SetKey(key);

        // IN C, THERE IS VALUE UNINITIALIZE VALUE ON IT, 204(0xCC)
        var headerArray = new byte[Marshal.SizeOf<PakHeader>()];
        Array.Fill(headerArray, (byte)0xCC);

        Console.WriteLine($"{BitConverter.ToUInt32(headerArray, 0)} {headerArray[4]} {BitConverter.ToUInt32(headerArray, 5)}");
        
        snow.DecryptBuffer(headerArray, pkgData, headerArray.Length);

        Console.WriteLine($"{BitConverter.ToUInt32(headerArray, 0)} {headerArray[4]} {BitConverter.ToUInt32(headerArray, 5)}");

        return new()
        { iChecksum = BitConverter.ToUInt32(headerArray, 0),
          iVersion  = headerArray[4],
          iEntries  = BitConverter.ToUInt32(headerArray, 5),
          pad       = headerArray[9..] }; }
}
