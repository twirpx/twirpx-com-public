using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using CLAP;
using static System.String;

namespace DupCheck {
    public class Program {

        // ReSharper disable UnusedParameter.Global
        // ReSharper disable UnusedMethodReturnValue.Global

        static Program() {
            string path_app_data = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string path_program = Path.Combine(path_app_data, "Twirpx\\DupCheck");
            if (!Directory.Exists(path_program)) {
                Directory.CreateDirectory(path_program);
            }

            DatPath = Path.Combine(path_program, "hash-feed.dat");
            TxtPath = Path.Combine(path_program, "hash-feed.txt");
            GzPath = Path.Combine(path_program, "hash-feed.gz");
        }

        public static string FeedUrl { get; } = "http://feed.twirpx.com/hash-feed.dat";

        public static string EncryptionKey { get; } = "5350408F3E5348CA";

        public static string DatPath { get; }

        public static string TxtPath { get; }

        public static string GzPath { get; }

        public static int Main(string[] args) {
            int result = Parser.Run<Program>(args);

            if (Debugger.IsAttached) {
                Console.WriteLine();
                Console.WriteLine("Press any key to exit...");

                Console.ReadKey();
            }

            return result;
        }

        [ Help ]
        [ Verb(Aliases = "help", IsDefault = true) ]
        public static void Help(string help) {
            Console.WriteLine("Usage:");
            Console.WriteLine("  DupCheck <command>");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  download [-force] - updates hash database");
            Console.WriteLine("  check [-path:\"<path>\"] [-delete] - check current (or specified) path and optionally delete duplicate files");
        }

        [ Error ]
        public static void HandleError(ExceptionContext context) {
            context.ReThrow = false;

            Console.WriteLine();

            Console.ForegroundColor = ConsoleColor.Red;

            Exception ex = context.Exception;
            while (ex != null) {
                Console.WriteLine("Error: {0} {1}", ex.GetType().Name, ex.Message);

                ex = ex.InnerException;
            }

            Console.ForegroundColor = ConsoleColor.Gray;
        }

        [ Verb(Aliases = "download") ]
        public static int Download(bool force = false) {
            bool process = force;

            FileInfo txt_fi = new FileInfo(TxtPath);
            if (txt_fi.Exists) {
                TimeSpan created_ago = DateTime.Now - txt_fi.CreationTime;
                if (created_ago.TotalDays > 1.0) {
                    process = true;
                } else {
                    Console.WriteLine("Hash-feed is up to date");
                }
            } else {
                process = true;
            }

            if (process) {
                DownloadDAT();

                return 0;
            } else {
                return 1;
            }
        }

        private static void DownloadDAT() {
            try {
                Console.WriteLine("Downloading hash-feed file...");

                if (File.Exists(DatPath)) {
                    File.Delete(DatPath);
                }

                Stopwatch stopwatch = new Stopwatch();
                stopwatch.Start();

                using (WebClient client = new WebClient()) {
                    client.DownloadFile(FeedUrl, DatPath);
                }

                stopwatch.Stop();

                Console.WriteLine("  File downloaded in ~{0:0}sec", stopwatch.Elapsed.TotalSeconds);

                ExtractDAT();
            } catch {
                if (File.Exists(TxtPath)) {
                    File.Delete(TxtPath);
                }
                throw;
            } finally {
                if (File.Exists(DatPath)) {
                    File.Delete(DatPath);
                }
            }
        }

        private static void ExtractDAT() {
            Console.WriteLine("Extracting hash-feed file...");

            using (Stream dat_stream = File.Open(DatPath, FileMode.Open, FileAccess.Read)) {
                if (dat_stream.Length < 56) {
                    throw new Exception("Hash-feed file too small");
                    
                }

                Console.WriteLine("Checking file signature...");

                byte[] signature = new byte[8];
                dat_stream.Read(signature, 0, signature.Length);

                if (signature[0] != 0x48 || signature[1] != 0x41 || signature[2] != 0x53 || signature[3] != 0x48 || signature[4] != 0x46 || signature[5] != 0x45 || signature[6] != 0x45 || signature[7] != 0x44) {
                    throw new Exception("Hash-feed file signature check failed");
                }

                byte[] buffer = new byte[16];

                dat_stream.Read(buffer, 0, buffer.Length);
                string txt_hash = BytesToHex(buffer);

                dat_stream.Read(buffer, 0, buffer.Length);
                string gz_hash = BytesToHex(buffer);

                dat_stream.Read(buffer, 0, buffer.Length);
                string dat_hash = BytesToHex(buffer);

                Console.WriteLine("Hashing encrypted stream...");
                string dat_actual = HashMD5(dat_stream);

                Console.WriteLine("Checking encrypted stream hash...");
                if (Compare(dat_hash, dat_actual, StringComparison.InvariantCultureIgnoreCase) != 0) {
                    throw new Exception(Format("Encrypted stream hash check failed ({0} expected {1} actual)", dat_hash, dat_actual));
                }

                try {
                    DecryptDAT(txt_hash, dat_stream, gz_hash);
                } finally {
                    if (File.Exists(GzPath)) {
                        File.Delete(GzPath);
                    }
                }
            }
        }

        private static void DecryptDAT(string txt_hash, Stream dat_stream, string gz_hash) {
            Console.WriteLine("Decrypting hash-feed...");

            using (Stream gz_stream = File.Open(GzPath, FileMode.Create, FileAccess.ReadWrite)) {
                byte[] key_bytes = BitConverter.GetBytes(Int64.Parse(EncryptionKey, NumberStyles.HexNumber));

                DESCryptoServiceProvider provider = new DESCryptoServiceProvider();
                provider.Key = key_bytes;
                provider.IV = key_bytes;

                ICryptoTransform decryptor = provider.CreateDecryptor();

                using (CryptoStream enc = new CryptoStream(dat_stream, decryptor, CryptoStreamMode.Read)) {
                    dat_stream.Seek(56, SeekOrigin.Begin);
                    CopyStream(enc, gz_stream);
                    gz_stream.Flush();
                }

                Console.WriteLine("Hashing compressed stream...");
                gz_stream.Seek(0, SeekOrigin.Begin);
                string gz_actual = HashMD5(gz_stream);

                Console.WriteLine("Checking compressed stream hash...");

                if (Compare(gz_hash, gz_actual, StringComparison.InvariantCultureIgnoreCase) != 0) {
                    throw new Exception(Format("Compressed stream hash check failed ({0} expected {1} actual)", gz_hash, gz_actual));
                }

                DecompressDAT(txt_hash, gz_stream);
            }
        }

        private static void DecompressDAT(string txt_hash, Stream gz_stream) {
            Console.WriteLine("Decompressing text file...");

            using (Stream txt_stream = File.Open(TxtPath, FileMode.Create, FileAccess.ReadWrite)) {
                using (GZipStream gz = new GZipStream(gz_stream, CompressionMode.Decompress)) {
                    gz_stream.Seek(0, SeekOrigin.Begin);
                    CopyStream(gz, txt_stream);
                }

                Console.WriteLine("Hashing text file...");
                txt_stream.Seek(0, SeekOrigin.Begin);
                string txt_actual = HashMD5(txt_stream);

                Console.WriteLine("Checking text file hash...");
                if (Compare(txt_hash, txt_actual, StringComparison.InvariantCultureIgnoreCase) != 0) {
                    throw new Exception(Format("Text file hash check failed ({0} expected {1} actual)", txt_hash, txt_actual));
                }

                Console.WriteLine("Done");
            }
        }

        private const string HEX = "0123456789ABCDEF";

        private static string BytesToHex(byte[] bytes) {
            char[] chars = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++) {
                chars[i * 2 + 0] = HEX[bytes[i] >> 4];
                chars[i * 2 + 1] = HEX[bytes[i] & 15];
            }
            return new string(chars);
        }

        private static string HashMD5(Stream stream) {
            using (MD5 md5 = new MD5CryptoServiceProvider()) {
                return BytesToHex(md5.ComputeHash(stream));
            }
        }

        private static void CopyStream(Stream src, Stream dst) {
            byte[] buffer = new byte[4096];

            int read = src.Read(buffer, 0, buffer.Length);
            while (read > 0) {
                dst.Write(buffer, 0, read);
                read = src.Read(buffer, 0, buffer.Length);
            }
        }

        private static readonly char[] SEPARATORS = { ' ' };
        
        [ Verb(Aliases = "check") ]
        public static int Check(string path = null, bool delete = false, bool verbose = false) {
            Download();

            if (IsNullOrEmpty(path)) {
                path = Directory.GetCurrentDirectory();
            } else {
                path = Path.GetFullPath(path);
            }

            Console.WriteLine("Loading hash-feed...");

            Dictionary<string, List<int>> hash_map = new Dictionary<string, List<int>>();
            int hash_count = 0;

            using (StreamReader reader = new StreamReader(TxtPath)) {
                while (!reader.EndOfStream) {
                    string line = reader.ReadLine();

                    // ReSharper disable once PossibleNullReferenceException
                    string[] parts = line.Split(SEPARATORS, StringSplitOptions.RemoveEmptyEntries);
                    
                    if (parts.Length < 3) {
                        continue;
                    }

                    if (!Int32.TryParse(parts[0], out int file_id)) {
                        continue;
                    }

                    if (!Int32.TryParse(parts[1], out _)) {
                        continue;
                    }

                    for (int i = 2; i < parts.Length; i++) {
                        string hash = parts[i].ToUpper();

                        if (!hash_map.TryGetValue(hash, out List<int> list)) {
                            list = new List<int>();
                            hash_map.Add(hash, list);
                        }

                        hash_count++;
                        list.Add(file_id);
                    }
                }
            }

            Console.WriteLine("  {0} file(s) and {1} hash(es) loaded", hash_map.Count, hash_count);

            Console.WriteLine("Checking for duplicate files...");

            if (delete) {
                Console.WriteLine("  Mode: scan & delete");
            } else {
                Console.WriteLine("  Mode: scan");
            }

            ScanDirectory(path, hash_map, delete, verbose);

            Console.WriteLine("Done");

            return 0;
        }

        private static void ScanDirectory(string directory_path, Dictionary<string, List<int>> hash_map, bool delete, bool verbose) {
            Console.WriteLine("Scanning {0}...", directory_path);

            foreach (string file_path in Directory.GetFiles(directory_path)) {
                ScanFile(file_path, hash_map, delete, verbose);
            }
            foreach (string sub_path in Directory.GetDirectories(directory_path)) {
                ScanDirectory(sub_path, hash_map, delete, verbose);
            }
        }

        private static void ScanFile(string file_path, Dictionary<string, List<int>> hash_map, bool delete, bool verbose) {
            try {
                if (verbose) {
                    Console.WriteLine("  {0}...", Path.GetFileName(file_path));
                }

                string file_hash;
                using (Stream stream = File.OpenRead(file_path)) {
                    file_hash = HashMD5(stream).ToUpper();
                }

                if (verbose) {
                    Console.WriteLine("    md5 = {0}", file_hash);
                }

                if (hash_map.TryGetValue(file_hash, out List<int> list)) {
                    Console.ForegroundColor = ConsoleColor.Yellow;

                    if (verbose) {
                        Console.WriteLine("    duplicates:");
                    } else {
                        Console.WriteLine("  {0} (md5 = {1}) duplicates:", Path.GetFileName(file_path), file_hash.ToLower());
                    }

                    foreach (int file_id in list) {
                        Console.WriteLine("    http://www.twirpx.com/file/{0}/", file_id);
                    }

                    Console.ForegroundColor = ConsoleColor.Gray;

                    if (delete) {
                        try {
                            File.Delete(file_path);
                            Console.WriteLine("    deleted");
                        } catch {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("    failed to delete");
                            Console.ForegroundColor = ConsoleColor.Gray;
                        }
                    }
                }
            } catch {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  {0} failed to scan", Path.GetFileName(file_path));
                Console.ForegroundColor = ConsoleColor.Gray;
            }
        }

    }
}