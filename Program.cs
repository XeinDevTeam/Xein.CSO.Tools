namespace Xein.CSO.Tools;

public static class Program
{
    public static void Error(string msg)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine(msg);
        Console.ReadKey();
        Environment.Exit(0);
    }
    
    public static void Main(string[] args)
    {
        Console.WriteLine("Hello World");
        
        // temp
        //args = new[] { "resource.nar", };
        args = new[] { "D:\\CSO\\Korea\\Counter-Strike Online\\Data\\Packer\\common_00191.pak", };

        if (args.Length < 1)
            Error("Missing Parameters");

        var filePath = args[0];

        if (!File.Exists(filePath))
            Error("File not found");

        FileInfo fi = new(filePath);

        if (fi.Extension is ".nar")
        {
            try
            {
                NexonArchive nar = new();
                nar.Load(fi.FullName, false);
                Console.WriteLine($"[NAR] loaded {fi.Name}");
                Console.ForegroundColor = ConsoleColor.Cyan;
                foreach (var entry in nar.FileEntries)
                    Console.WriteLine($"File: {entry.path,-64} | {entry.extractedSize,-12} | Type: {entry.storedType,-20} | Date: {entry.lastModifiedTime}");
                Console.ResetColor();
            }
            catch (Exception e)
            {
                Error($"Loading NAR file error: {e.Message}\n{e.StackTrace}");
            }
        }
        else if (fi.Extension is ".pak")
        {
            var pakBuf = File.ReadAllBytes(fi.FullName);

            PakFile pak = new(pakBuf, fi.Name);
            if (!pak.ParseHeader())
                Error($"Failed to parse PAK file header [not CSO PAK files]");
            if (!pak.ParseEntries())
                Error($"Failed to parse PAK file entries [Probably corrupted?]");

            Console.ForegroundColor = ConsoleColor.Cyan;
            foreach (var entry in pak.entries)
                Console.WriteLine($"File: {entry.szFilePath,-64} | {entry.iSizeOriginal,-12} | Type: {entry.iType,-20} | Date: {entry.iUnk}");
            Console.ResetColor();
        }
        else
        {
            Error($"File format not supported");
        }

        Console.ReadKey();
    }
}