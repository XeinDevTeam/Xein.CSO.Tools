using System.Collections.ObjectModel;
using System.Text;

using ICSharpCode.SharpZipLib.BZip2;

namespace Xein.CSO.Tools;

public enum NexonArchiveFileEntryType
{
    Raw,
    Encoded,
    EncodedAndCompressed,
}

public sealed class NexonArchiveFileEntry
{
    internal NexonArchiveFileEntry(NexonArchive archive)
    {
        this.archive = archive;
    }
    
    private static DateTime FromEpoch(int epoch) => new(epoch * 10000000L + 621355968000000000L);

    internal int Load(byte[] header, int offset)
    {
        int result;
        try
        {
            int pathSize = BitConverter.ToUInt16(header, offset);
            path             = Encoding.Unicode.GetString(header, offset + 2, pathSize);
            storedType       = (NexonArchiveFileEntryType)BitConverter.ToInt32(header, offset + 2 + pathSize);
            this.offset      = BitConverter.ToUInt32(header, offset + 2 + pathSize + 4);
            storedSize       = BitConverter.ToInt32(header, offset  + 2 + pathSize + 8);
            extractedSize    = BitConverter.ToInt32(header, offset  + 2 + pathSize + 12);
            lastModifiedTime = FromEpoch(BitConverter.ToInt32(header, offset + 2 + pathSize + 16));
            checksum         = BitConverter.ToUInt32(header, offset + 2 + pathSize + 20);
            result           = 2 + pathSize + 24;
        }
        catch (ArgumentOutOfRangeException ex)
        {
            throw new InvalidDataException("NAR file entry is invalid.", ex);
        }

        return result;
    }

    public long Extract(Stream outputStream)
    {
        if (outputStream == null)
            throw new ArgumentNullException("outputStream");
        if (!outputStream.CanWrite)
            throw new ArgumentException("Cannot write to stream.", "outputStream");

        if (extractedSize == 0L)
            return 0L;

        long result;
        lock (archive.Stream)
        {
            Stream readStream = new BoundedStream(archive.Stream, offset, storedSize);
            readStream.Position = 0L;
            switch (storedType)
            {
                case NexonArchiveFileEntryType.Raw:
                    break;
                case NexonArchiveFileEntryType.Encoded:
                    readStream = new NexonArchiveFileDecoderStream(readStream, path);
                    break;
                case NexonArchiveFileEntryType.EncodedAndCompressed:
                    readStream = new NexonArchiveFileDecompressStream(new NexonArchiveFileDecoderStream(readStream, path), extractedSize);
                    break;
                default:
                    throw new NotSupportedException("Unsupported file storage type: " + storedType + ".");
            }
            lock (outputStream)
            {
                var buffer      = new byte[8192];
                var   totalLength = 0L;
                int    length;
                while ((length = readStream.Read(buffer, 0, 8192)) > 0)
                {
                    outputStream.Write(buffer, 0, length);
                    totalLength += length;
                }
                result = totalLength;
            }
        }

        return result;
    }

    public bool Verify()
    {
        var crc = new ICSharpCode.SharpZipLib.Checksum.Crc32();
        lock (archive.Stream)
        {
            Stream readStream = new BoundedStream(archive.Stream, offset, storedSize);
            readStream.Position = 0L;
            var buffer = new byte[8192];
            int    length;
            while ((length = readStream.Read(buffer, 0, 8192)) > 0)
            {
                crc.Update(buffer);
            }
        }

        return checksum == (ulong)crc.Value;
    }

    public NexonArchive              archive;
    public string                    path;
    public NexonArchiveFileEntryType storedType;
    public long                      offset;
    public long                      storedSize;
    public long                      extractedSize;
    public DateTime                  lastModifiedTime;
    public uint                      checksum;
}

public sealed class NexonArchive : IDisposable
{
    internal Stream Stream => stream;

    public ReadOnlyCollection<NexonArchiveFileEntry> FileEntries => fileEntries.AsReadOnly();

    public void Load(string fileName, bool writable)
    {
        if (stream != null)
        {
            throw new InvalidOperationException("The archive must be disposed before it can be loaded again.");
        }
        Load(new FileStream(fileName, FileMode.Open, writable ? FileAccess.ReadWrite : FileAccess.Read, FileShare.Read), writable);
    }

    public void Load(Stream stream, bool writable)
    {
        if (stream == null)
        {
            throw new ArgumentNullException("stream");
        }
        if (!stream.CanRead)
        {
            throw new ArgumentException("Cannot read from stream.", "stream");
        }
        if (!stream.CanSeek)
        {
            throw new ArgumentException("Cannot seek in stream.", "stream");
        }
        if (writable && !stream.CanWrite)
        {
            throw new ArgumentException("Cannot write to stream.", "stream");
        }
        if (this.stream != null)
        {
            throw new InvalidOperationException("The archive must be disposed before it can be loaded again.");
        }
        int    headerSize;
        byte[] header;
        lock (stream)
        {
            stream.Position = 0L;
            this.stream     = stream;
            var reader = new BinaryReader(this.stream);
            if (reader.ReadInt32() != 5390670)
            {
                throw new InvalidDataException("NAR file invalid.");
            }
            if (reader.ReadInt32() != 16777216)
            {
                throw new InvalidDataException("NAR file version invalid.");
            }
            if (this.stream.Length < 16L)
            {
                throw new InvalidDataException("NAR file is not long enough to be valid.");
            }
            this.stream.Seek(-4L, SeekOrigin.End);
            if (reader.ReadInt32() != 5390670)
            {
                throw new InvalidDataException("NAR end file signature is invalid.");
            }
            this.stream.Seek(-8L, SeekOrigin.Current);
            headerSize = (reader.ReadInt32() ^ 1081496863);
            if (this.stream.Length < headerSize + 16)
            {
                throw new InvalidDataException("NAR file is not long enough to be valid.");
            }
            this.stream.Seek(-4 - headerSize, SeekOrigin.Current);
            header = reader.ReadBytes(headerSize);
        }
        for (var i = 0; i < header.Length; i++)
        {
            var array = header;
            var    num   = i;
            array[num] ^= HeaderXor[i & 15];
        }
        using (var decompressedHeaderStream = new MemoryStream(headerSize))
        {
            BZip2.Decompress(new MemoryStream(header, false), decompressedHeaderStream, false);
            var decompressedHeader = decompressedHeaderStream.ToArray();
            LoadHeader(decompressedHeader);
        }
    }

    private void LoadHeader(byte[] header)
    {
        if (header.Length < 4)
        {
            throw new InvalidDataException("NAR header is invalid.");
        }
        var version = BitConverter.ToInt32(header, 0);
        if (version != 1)
        {
            throw new InvalidDataException("NAR header version is invalid.");
        }
        if (header.Length < 16)
        {
            throw new InvalidDataException("NAR header is invalid.");
        }
        BitConverter.ToInt32(header, 4);
        BitConverter.ToInt32(header, 8);
        BitConverter.ToInt32(header, 12);
        var directoryCount = BitConverter.ToInt32(header, 16);
        if (directoryCount < 0)
        {
            throw new InvalidDataException("Directory entry count is too large.");
        }
        var entryOffset = 20;
        for (var i = 0; i < directoryCount; i++)
        {
            var fileEntry = new NexonArchiveFileEntry(this);
            entryOffset += fileEntry.Load(header, entryOffset);
            fileEntries.Add(fileEntry);
        }
    }

    public void Close()
    {
        fileEntries.Clear();
        stream.Close();
    }

    public void Dispose()
    {
        Close();
    }

    private static readonly byte[] HeaderXor = new byte[] { 25, 91, 123, 44, 101, 94, 121, 37, 110, 75, 7, 33, 98, 127, 0, 41 };

    private Stream                      stream;
    private List<NexonArchiveFileEntry> fileEntries = new List<NexonArchiveFileEntry>();
}
