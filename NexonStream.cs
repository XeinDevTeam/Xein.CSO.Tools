using System.Text;

namespace Xein.CSO.Tools;

internal sealed class CircularBuffer
{
    public CircularBuffer(int length)
    {
        data = new byte[length];
    }
    
    public int Length => length;

    public void Append(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (count == 0)
            return;

        if (count >= data.Length)
        {
            Buffer.BlockCopy(buffer, offset + (count - data.Length), data, 0, data.Length);
            source = 0;
            length = data.Length;
            return;
        }
        
        if (source == data.Length)
            source = 0;

        var initialCopyLength = Math.Min(data.Length - source, count);
        Buffer.BlockCopy(buffer, offset, data, source, initialCopyLength);
        if (count > initialCopyLength)
            Buffer.BlockCopy(buffer, offset + initialCopyLength, data, 0, count - initialCopyLength);

        source = (source + count) % data.Length;
        length = Math.Min(length + count, data.Length);
    }
    
    public void Copy(int distance, byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || offset + count > buffer.Length || count > length)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (distance <= 0 || distance > length)
            throw new ArgumentOutOfRangeException(nameof(distance));
        if (count == 0)
            return;

        var copySource = source - distance;
        if (copySource < 0)
            copySource = data.Length + copySource;

        var copyLength       = data.Length - copySource;
        var actualCopyLength = Math.Min(count, copyLength);
        Buffer.BlockCopy(data, copySource, buffer, offset, actualCopyLength);
        if (count > copyLength)
            Buffer.BlockCopy(data, 0, buffer, offset + actualCopyLength, count - actualCopyLength);
    }
    
    private readonly byte[] data;
    private          int    source;
    private          int    length;
}

internal sealed class BoundedStream : Stream
{
    public BoundedStream(Stream stream, long offset, long length)
    {
        baseStream = stream;
        baseOffset = offset;
        baseLength = length;
        position   = baseStream.Position - baseOffset;

        if (position < 0L)
        {
            baseStream.Seek(-position, SeekOrigin.Current);
            position = 0L;
        }
    }

    public override bool CanRead  => baseStream.CanRead;
    public override bool CanSeek  => baseStream.CanSeek;
    public override bool CanWrite => baseStream.CanWrite;
    public override long Length   => baseLength;

    public override long Position
    {
        get => position;
        set
        {
            if (!CanSeek)
                throw new NotSupportedException("Cannot seek in stream.");
            if (value < 0L || value > baseLength)
                throw new ArgumentOutOfRangeException(nameof(value));

            baseStream.Position = baseOffset          + value;
            position            = baseStream.Position - baseOffset;
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            baseStream.Dispose();
    }

    public override void Flush() => baseStream.Flush();

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (position + count > baseLength)
            count = Convert.ToInt32(Math.Min(baseLength - position, 2147483647L));

        var bytesRead = baseStream.Read(buffer, offset, count);
        position += bytesRead;
        return bytesRead;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        if (!CanSeek)
            throw new NotSupportedException("Cannot seek in stream.");

        long temp;
        switch (origin)
        {
            case SeekOrigin.Begin:
                if (offset < 0L || offset > baseLength)
                    throw new ArgumentOutOfRangeException(nameof(offset));
                temp = baseStream.Seek(baseOffset + offset, SeekOrigin.Begin);
                break;

            case SeekOrigin.Current:
                temp = position + offset;
                if (temp < 0L || temp > baseLength)
                    throw new ArgumentOutOfRangeException(nameof(offset));
                temp = baseStream.Seek(offset, SeekOrigin.Current);
                break;

            case SeekOrigin.End:
                temp = baseLength + offset;
                if (temp < 0L || temp > baseLength)
                    throw new ArgumentOutOfRangeException(nameof(offset));
                temp = baseStream.Seek(offset, SeekOrigin.End);
                break;

            default:
                throw new ArgumentException("Not a valid seek origin.", nameof(origin));
        }
        
        position = temp - baseOffset;
        return position;
    }

    public override void SetLength(long value)
    {
        if (value < baseOffset + baseLength)
            throw new ArgumentException("Value is less than the stream's boundaries.", nameof(value));
        baseStream.SetLength(value);
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));
        if (position + count > baseLength)
            throw new ArgumentOutOfRangeException(nameof(count));

        baseStream.Write(buffer, offset, count);
        position += count;
    }

    private readonly Stream baseStream;
    private readonly long   baseOffset;
    private readonly long   baseLength;
    private          long   position;
}

internal sealed class NexonArchiveFileDecoderStream : Stream
{
    
    public NexonArchiveFileDecoderStream(Stream stream, string path)
    {
        baseStream = stream;
        GenerateKey(path);
    }
    
    public override bool CanRead  => true;
    public override bool CanSeek  => true;
    public override bool CanWrite => false;
    public override long Length   => baseStream.Length;
    public override long Position { get => baseStream.Position; set => baseStream.Position = value; }
    
    private static uint PythonHash(byte[] data)
    {
        var hash = 0U;
        foreach (var t in data)
            hash = hash * 1000003U ^ t;
        return hash ^ (uint)data.Length;
    }
    
    private void GenerateKey(string path)
    {
        var seed = PythonHash(Encoding.ASCII.GetBytes(path));
        for (var i = 0; i < 16; i++)
        {
            seed   = seed * 1103515245U + 12345U;
            key[i] = (byte)(seed & 255U);
        }
    }
    
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            baseStream.Dispose();
    }
    
    public override void Flush() { }
    
    public override int Read(byte[] buffer, int offset, int count)
    {
        var tempOffset = Position;
        var  length     = baseStream.Read(buffer, offset, count);
        
        for (var i = 0; i < length; i++)
        {
            var num = offset + i;
            buffer[num] ^= key[(int)(checked((IntPtr)(unchecked(tempOffset + i) & 15L)))];
        }

        return length;
    }
    
    public override long Seek(long offset, SeekOrigin origin) => baseStream.Seek(offset, origin);
    
    public override void SetLength(long value) => throw new NotSupportedException("Cannot write to stream.");

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("Cannot write to stream.");

    private readonly Stream baseStream;
    private readonly byte[] key = new byte[16];
}

internal sealed class NexonArchiveFileDecompressStream : Stream
{
    public NexonArchiveFileDecompressStream(Stream stream, long length)
    {
        baseStream = stream;
        Length     = length;
    }
    
    public override bool CanRead  => true;
    public override bool CanSeek  => false;
    public override bool CanWrite => false;
    public override long Length   { get; }
    public override long Position { get => outputPosition; set => throw new NotSupportedException("Cannot seek in stream."); }
    
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
            baseStream.Dispose();
    }
    
    public override void Flush() { }
    
    private byte ReadByteChecked()
    {
        var temp = baseStream.ReadByte();
        if (temp < 0)
            throw new EndOfStreamException();
        return Convert.ToByte(temp);
    }
    
    private void ReadHeader()
    {
        var tempByte  = ReadByteChecked();
        var operation = tempByte >> 5;
        var length    = tempByte & 31;
        
        if (operation == 0)
        {
            lastReadDistance = 0;
            lastReadLength   = length + 1;
            return;
        }
        
        if (operation == 7)
            operation += ReadByteChecked();

        operation        += 2;
        length           =  (length << 8 | ReadByteChecked()) + 1;
        lastReadDistance =  length;
        lastReadLength   =  operation;
    }
    
    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new ArgumentNullException(nameof(buffer));
        if (offset < 0)
            throw new ArgumentOutOfRangeException(nameof(offset));
        if (count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(count));

        if (count == 0)
            return 0;
        if (baseStream.Position >= baseStream.Length)
            return 0;
        if (Position >= Length)
            return 0;

        count = Convert.ToInt32(Math.Min(Length - Position, count));
        var totalCount      = count;
        var totalCountFixed = totalCount;
        while (totalCount > 0)
        {
            if (lastReadLength == 0)
            {
                ReadHeader();
                if (lastReadDistance > 0 && lastReadDistance > dictionary.Length)
                    throw new InvalidDataException("Distance is larger than the dictionary's current length.");
            }
            
            if (count > lastReadLength)
                count = lastReadLength;

            if (lastReadDistance == 0)
            {
                var lengthRead = baseStream.Read(buffer, offset, count);
                if (lengthRead == 0)
                    throw new EndOfStreamException("Expected " + lastReadLength + " more bytes in compressed stream.");

                dictionary.Append(buffer, offset, lengthRead);
                lastReadLength -= lengthRead;
                outputPosition += lengthRead;
                totalCount          -= lengthRead;
                offset              += lengthRead;
            }
            else
            {
                while (count > 0)
                {
                    dictionary.Copy(lastReadDistance, buffer, offset, 1);
                    dictionary.Append(buffer, offset, 1);
                    lastReadLength--;
                    outputPosition += 1L;
                    totalCount--;
                    offset++;
                    count--;
                }
            }
            
            count = totalCount;
        }
        return totalCountFixed;
    }
    
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException("Cannot seek in stream.");

    public override void SetLength(long value) => throw new NotSupportedException("Cannot write to stream.");

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException("Cannot write to stream.");

    private readonly Stream         baseStream;
    private          long           outputPosition;
    private readonly CircularBuffer dictionary = new(8192);
    private          int            lastReadDistance;
    private          int            lastReadLength;
}
