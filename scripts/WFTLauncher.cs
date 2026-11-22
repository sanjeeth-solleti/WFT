using System;
using System.IO;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;
using System.Collections.Generic;
using Microsoft.Win32;

[assembly: AssemblyTitle("Windows Forensic Toolkit (WFT)")]
[assembly: AssemblyDescription("Windows Forensic Toolkit (WFT) Enterprise Workstation")]
[assembly: AssemblyProduct("Windows Forensic Toolkit (WFT)")]
[assembly: AssemblyCompany("Windows Forensic Toolkit")]
[assembly: AssemblyVersion("2.0.0.0")]
[assembly: AssemblyFileVersion("2.0.0.0")]

namespace WFTLauncher
{
    static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AttachConsole(uint dwProcessId);

        const uint ATTACH_PARENT_PROCESS = unchecked((uint)-1);

        static void InitConsoleOutput(bool isHeadless)
        {
            if (isHeadless)
            {
                if (AttachConsole(ATTACH_PARENT_PROCESS))
                {
                    try
                    {
                        var standardOutput = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                        var standardError = new StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
                        Console.SetOut(standardOutput);
                        Console.SetError(standardError);
                    }
                    catch { }
                }
            }
        }

        static bool EnvBool(string name)
        {
            string val = Environment.GetEnvironmentVariable(name);
            if (string.IsNullOrWhiteSpace(val)) return false;
            val = val.Trim();
            return val.Equals("1", StringComparison.OrdinalIgnoreCase)
                || val.Equals("true", StringComparison.OrdinalIgnoreCase)
                || val.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

        static void ShowErrorOrStderr(bool isHeadless, string message, string title)
        {
            if (isHeadless)
            {
                Console.Error.WriteLine("[" + title + "] " + message);
                Console.Error.Flush();
            }
            else
            {
                MessageBox.Show(message, title, MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        static bool IsDirectoryWritable(string dirPath)
        {
            if (string.IsNullOrWhiteSpace(dirPath) || !Directory.Exists(dirPath)) return false;
            string probe = Path.Combine(
                dirPath,
                ".wft_write_test_" + Process.GetCurrentProcess().Id + "_" + Guid.NewGuid().ToString("N")
            );
            try
            {
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return true;
            }
            catch
            {
                try { if (File.Exists(probe)) File.Delete(probe); } catch { }
                return false;
            }
        }

        static bool IsTcpPortListening(int port)
        {
            try
            {
                using (var client = new System.Net.Sockets.TcpClient())
                {
                    var result = client.BeginConnect("127.0.0.1", port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(150);
                    if (!success) return false;
                    client.EndConnect(result);
                    return true;
                }
            }
            catch { return false; }
        }

        static string GetRecentLogLines(string baseDir, int maxLines)
        {
            try
            {
                string logPath = Path.Combine(baseDir, "logs", "wft_runtime.log");
                if (!File.Exists(logPath))
                {
                    string appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WFT", "logs", "wft_runtime.log");
                    if (File.Exists(appData)) logPath = appData;
                }
                if (File.Exists(logPath))
                {
                    var allLines = new List<string>();
                    using (var fs = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    using (var reader = new StreamReader(fs))
                    {
                        string l;
                        while ((l = reader.ReadLine()) != null)
                        {
                            if (!string.IsNullOrWhiteSpace(l)) allLines.Add(l.Trim());
                        }
                    }
                    int start = Math.Max(0, allLines.Count - maxLines);
                    var recent = new List<string>();
                    for (int i = start; i < allLines.Count; i++)
                    {
                        recent.Add(allLines[i]);
                    }
                    if (recent.Count > 0) return string.Join("\n", recent.ToArray());
                }
            }
            catch { }
            return "";
        }

        static bool LaunchDesktopApp(int port)
        {
            string url = "http://127.0.0.1:" + port;
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string profileDir = Path.Combine(localAppData, "WFT", "browser_profile");
            try { Directory.CreateDirectory(profileDir); } catch { }

            var candidates = new List<string> {
                Path.Combine(progFiles, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(progFilesX86, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(localAppData, @"Google\Chrome\Application\chrome.exe")
            };
            if (EnvBool("WFT_ALLOW_EDGE"))
            {
                candidates.Add(Path.Combine(progFilesX86, @"Microsoft\Edge\Application\msedge.exe"));
                candidates.Add(Path.Combine(progFiles, @"Microsoft\Edge\Application\msedge.exe"));
                candidates.Add(Path.Combine(localAppData, @"Microsoft\Edge\Application\msedge.exe"));
            }

            foreach (var browser in candidates)
            {
                if (File.Exists(browser))
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = browser;
                        psi.Arguments = "--app=\"" + url + "\" --user-data-dir=\"" + profileDir + "\" --no-first-run --no-default-browser-check --disable-background-mode --no-service-autorun --new-window";
                        psi.UseShellExecute = false;
                        Process.Start(psi);
                        return true;
                    }
                    catch { }
                }
            }

            try
            {
                Process.Start(url);
                return true;
            }
            catch { return false; }
        }

        static int GetPythonTier(string candidate, bool allowWindowsAppsOverride = false)
        {
            if (string.IsNullOrWhiteSpace(candidate)) return 0;
            try
            {
                string fullPath = Path.GetFullPath(candidate.Trim().Trim('"'));
                if (!File.Exists(fullPath)) return 0;

                bool isWinApps = fullPath.IndexOf(@"\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase) >= 0;
                if (isWinApps && !allowWindowsAppsOverride)
                {
                    return 0;
                }

                try
                {
                    var fi = new FileInfo(fullPath);
                    if (!isWinApps && fi.Length <= 0) return 0;
                }
                catch { }

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fullPath;
                psi.Arguments = "-c \"import sys; sys.exit(2 if (3, 10) <= sys.version_info < (3, 13) else (1 if sys.version_info >= (3, 13) else 0))\"";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                using (Process proc = Process.Start(psi))
                {
                    if (!proc.WaitForExit(5000))
                    {
                        try { proc.Kill(); } catch { }
                        return 0;
                    }
                    if (proc.ExitCode == 2) return 2; // Preferred compatible (3.10 - 3.12)
                    if (proc.ExitCode == 1) return 1; // Fallback (3.13+)
                    return 0;
                }
            }
            catch
            {
                return 0;
            }
        }

        static bool IsUsablePython(string candidate, bool allowWindowsAppsOverride = false)
        {
            return GetPythonTier(candidate, allowWindowsAppsOverride) > 0;
        }

        static string ResolveFromPyLauncher(ref string fallbackPy)
        {
            string[] pyLauncherCandidates = new string[] {
                "py.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "py.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "py.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Python\Launcher\py.exe"),
                Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles") ?? @"C:\Program Files", @"Python Launcher\py.exe"),
                Path.Combine(Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)", @"Python Launcher\py.exe")
            };

            string[] pyVersions = new string[] { "-3.12", "-3.11", "-3.10", "-3" };

            foreach (var ver in pyVersions)
            {
                foreach (var pyCmd in pyLauncherCandidates)
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo();
                        psi.FileName = pyCmd;
                        psi.Arguments = ver + " -c \"import sys; print(sys.executable)\"";
                        psi.UseShellExecute = false;
                        psi.CreateNoWindow = true;
                        psi.RedirectStandardOutput = true;
                        psi.RedirectStandardError = true;
                        using (Process proc = Process.Start(psi))
                        {
                            if (proc.WaitForExit(5000) && proc.ExitCode == 0)
                            {
                                string output = (proc.StandardOutput.ReadToEnd() ?? "").Trim();
                                if (!string.IsNullOrWhiteSpace(output))
                                {
                                    int tier = GetPythonTier(output, true);
                                    if (tier == 2) return Path.GetFullPath(output);
                                    if (tier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(output);
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            return null;
        }

        static IEnumerable<string> GetRegistryPythons()
        {
            var results = new List<string>();
            try
            {
                var hives = new RegistryHive[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine };
                var views = Environment.Is64BitOperatingSystem
                    ? new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 }
                    : new RegistryView[] { RegistryView.Default };

                foreach (var hive in hives)
                {
                    foreach (var view in views)
                    {
                        try
                        {
                            using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                            using (var coreKey = baseKey.OpenSubKey(@"Software\Python\PythonCore"))
                            {
                                if (coreKey == null) continue;
                                string[] subKeys;
                                try { subKeys = coreKey.GetSubKeyNames(); } catch { continue; }
                                Array.Sort(subKeys, (a, b) => string.Compare(b, a, StringComparison.OrdinalIgnoreCase));
                                foreach (var ver in subKeys)
                                {
                                    try
                                    {
                                        using (var installKey = coreKey.OpenSubKey(ver + @"\InstallPath"))
                                        {
                                            if (installKey != null)
                                            {
                                                object exePath = installKey.GetValue("ExecutablePath");
                                                if (exePath != null && !string.IsNullOrWhiteSpace(exePath.ToString()))
                                                {
                                                    results.Add(exePath.ToString().Trim());
                                                }
                                                object defPath = installKey.GetValue("");
                                                if (defPath != null && !string.IsNullOrWhiteSpace(defPath.ToString()))
                                                {
                                                    results.Add(Path.Combine(defPath.ToString().Trim(), "python.exe"));
                                                }
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
            return results;
        }

        static string ResolvePython()
        {
            string explicitPy = Environment.GetEnvironmentVariable("WFT_PYTHON_EXE");
            if (!string.IsNullOrWhiteSpace(explicitPy))
            {
                int expTier = GetPythonTier(explicitPy, true);
                if (expTier > 0) return Path.GetFullPath(explicitPy.Trim().Trim('"'));
                if (string.Equals(Environment.GetEnvironmentVariable("WFT_PYTHON_STRICT"), "1", StringComparison.Ordinal))
                    return null;
            }

            string fallbackPy = null;

            var pathList = new List<string>();
            var windowsAppsList = new List<string>();
            try
            {
                string p1 = Environment.GetEnvironmentVariable("PATH") ?? "";
                string p2 = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.User) ?? "";
                string p3 = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                pathList.AddRange(p1.Split(';'));
                pathList.AddRange(p2.Split(';'));
                pathList.AddRange(p3.Split(';'));
            }
            catch { }

            var seenDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var nonWaDirs = new List<string>();
            foreach (var d in pathList)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                string cleanDir = d.Trim().Trim('"');
                if (!seenDirs.Add(cleanDir)) continue;
                try
                {
                    string normDir = cleanDir.TrimEnd('\\', '/');
                    if (normDir.EndsWith(@"\Microsoft\WindowsApps", StringComparison.OrdinalIgnoreCase))
                    {
                        windowsAppsList.Add(cleanDir);
                    }
                    else
                    {
                        nonWaDirs.Add(cleanDir);
                    }
                }
                catch { }
            }

            // 1. Probe non-WindowsApps PATH entries
            foreach (var dir in nonWaDirs)
            {
                foreach (var exeName in new string[] { "python.exe", "python3.exe" })
                {
                    try
                    {
                        string cand = Path.Combine(dir, exeName);
                        int tier = GetPythonTier(cand, false);
                        if (tier == 2) return Path.GetFullPath(cand);
                        if (tier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(cand);
                    }
                    catch { }
                }
            }

            // 2. Probe WindowsApps PATH entries
            foreach (var waDir in windowsAppsList)
            {
                foreach (var exeName in new string[] { "python.exe", "python3.exe" })
                {
                    try
                    {
                        string cand = Path.Combine(waDir, exeName);
                        int tier = GetPythonTier(cand, true);
                        if (tier == 2) return Path.GetFullPath(cand);
                        if (tier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(cand);
                    }
                    catch { }
                }
            }

            // 3. Probe py.exe PEP 397 launcher
            string fromPy = ResolveFromPyLauncher(ref fallbackPy);
            if (!string.IsNullOrEmpty(fromPy)) return fromPy;

            // 4. Probe Registry pythons
            foreach (var regCandidate in GetRegistryPythons())
            {
                int tier = GetPythonTier(regCandidate, false);
                if (tier == 2) return Path.GetFullPath(regCandidate);
                if (tier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(regCandidate);
            }

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string progFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string progFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string sysDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            string baseDir = Environment.GetEnvironmentVariable("WFT_BASE_DIR");
            if (string.IsNullOrWhiteSpace(baseDir)) baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // 5. Probe common disk locations
            string[] common = new string[] {
                Path.Combine(baseDir, @".venv\Scripts\python.exe"),
                Path.Combine(baseDir, @"venv\Scripts\python.exe"),
                Path.Combine(baseDir, @"env\Scripts\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python312\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python311\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python310\python.exe"),
                Path.Combine(progFiles, @"Python312\python.exe"),
                Path.Combine(progFiles, @"Python311\python.exe"),
                Path.Combine(progFiles, @"Python310\python.exe"),
                Path.Combine(progFilesX86, @"Python312\python.exe"),
                Path.Combine(progFilesX86, @"Python311\python.exe"),
                Path.Combine(progFilesX86, @"Python310\python.exe"),
                Path.Combine(sysDrive, @"Python312\python.exe"),
                Path.Combine(sysDrive, @"Python311\python.exe"),
                Path.Combine(sysDrive, @"Python310\python.exe"),
                Path.Combine(sysDrive, @"tools\python312\python.exe"),
                Path.Combine(sysDrive, @"tools\python311\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\chocolatey\bin\python3.12.exe"),
                Path.Combine(sysDrive, @"ProgramData\chocolatey\bin\python3.11.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python313\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python314\python.exe"),
                Path.Combine(progFiles, @"Python313\python.exe"),
                Path.Combine(progFiles, @"Python314\python.exe"),
                Path.Combine(progFilesX86, @"Python313\python.exe"),
                Path.Combine(progFilesX86, @"Python314\python.exe"),
                Path.Combine(sysDrive, @"Python313\python.exe"),
                Path.Combine(sysDrive, @"Python314\python.exe"),
                Path.Combine(sysDrive, @"python\python.exe"),
                Path.Combine(sysDrive, @"python3\python.exe"),
                Path.Combine(sysDrive, @"tools\python313\python.exe"),
                Path.Combine(sysDrive, @"tools\python314\python.exe"),
                Path.Combine(sysDrive, @"tools\python3\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\chocolatey\bin\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\chocolatey\bin\python3.exe"),
                Path.Combine(sysDrive, @"ProgramData\chocolatey\bin\python3.13.exe"),
                Path.Combine(userProfile, @"anaconda3\python.exe"),
                Path.Combine(userProfile, @"miniconda3\python.exe"),
                Path.Combine(userProfile, @"miniforge3\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\anaconda3\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\miniconda3\python.exe"),
                Path.Combine(sysDrive, @"ProgramData\miniforge3\python.exe")
            };
            foreach (var cand in common)
            {
                int tier = GetPythonTier(cand, false);
                if (tier == 2) return Path.GetFullPath(cand);
                if (tier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(cand);
            }

            string defaultWa = Path.Combine(localAppData, @"Microsoft\WindowsApps\python.exe");
            int waTier = GetPythonTier(defaultWa, true);
            if (waTier == 2) return Path.GetFullPath(defaultWa);
            if (waTier == 1 && fallbackPy == null) fallbackPy = Path.GetFullPath(defaultWa);

            return fallbackPy;
        }

        static int RunProcess(string fileName, string arguments, string workingDir, bool isHeadless)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = fileName;
            psi.Arguments = arguments;
            psi.WorkingDirectory = workingDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = isHeadless;
            if (isHeadless)
            {
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
            }

            try
            {
                using (Process proc = Process.Start(psi))
                {
                    if (isHeadless)
                    {
                        proc.OutputDataReceived += (s, e) => { if (e.Data != null) Console.Out.WriteLine(e.Data); };
                        proc.ErrorDataReceived += (s, e) => { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                        proc.BeginOutputReadLine();
                        proc.BeginErrorReadLine();
                    }
                    proc.WaitForExit();
                    return proc.ExitCode;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Failed to run " + fileName + ": " + ex.Message);
                return -1;
            }
        }

        [STAThread]
        static int Main(string[] args)
        {
            if (args == null) args = new string[0];

            string baseDirOverride = Environment.GetEnvironmentVariable("WFT_BASE_DIR");
            string baseDir = !string.IsNullOrWhiteSpace(baseDirOverride)
                ? Path.GetFullPath(baseDirOverride.Trim())
                : AppDomain.CurrentDomain.BaseDirectory;
            try { Environment.CurrentDirectory = baseDir; } catch { }

            bool forceSetup = false;
            bool setupOnly = EnvBool("WFT_SETUP_ONLY");
            bool isHeadless = EnvBool("WFT_HEADLESS")
                || EnvBool("WFT_NONINTERACTIVE")
                || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PYTEST_CURRENT_TEST"));

            List<string> passthroughArgs = new List<string>();
            foreach (var arg in args)
            {
                if (string.IsNullOrWhiteSpace(arg)) continue;
                if (arg.Equals("--setup", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("/setup", StringComparison.OrdinalIgnoreCase) ||
                    arg.Equals("--reinstall", StringComparison.OrdinalIgnoreCase))
                {
                    forceSetup = true;
                }
                else if (arg.Equals("--setup-only", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("/setup-only", StringComparison.OrdinalIgnoreCase))
                {
                    setupOnly = true;
                }
                else if (arg.Equals("--headless", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("/headless", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--non-interactive", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("--stop", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("/stop", StringComparison.OrdinalIgnoreCase) ||
                         arg.Equals("-stop", StringComparison.OrdinalIgnoreCase))
                {
                    isHeadless = true;
                    if (arg.IndexOf("stop", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        passthroughArgs.Add(arg);
                    }
                }
                else
                {
                    passthroughArgs.Add(arg);
                }
            }
            if (setupOnly) isHeadless = true;
            InitConsoleOutput(isHeadless);

            string pythonExe = ResolvePython();
            if (string.IsNullOrEmpty(pythonExe))
            {
                ShowErrorOrStderr(
                    isHeadless,
                    "Python 3.10+ was not found on your system PATH or standard installation directories.\n\n" +
                    "Please install Python 3.10, 3.11, 3.12, or 3.13+ from https://www.python.org\n" +
                    "and ensure 'Add Python to PATH' is selected during installation.",
                    "Windows Forensic Toolkit (WFT) - Python Prerequisite Missing"
                );
                return 1;
            }

            try
            {
                string pyDir = Path.GetDirectoryName(pythonExe);
                if (!string.IsNullOrWhiteSpace(pyDir))
                {
                    string pyScripts = Path.Combine(pyDir, "Scripts");
                    string curPath = Environment.GetEnvironmentVariable("PATH") ?? "";
                    Environment.SetEnvironmentVariable("PATH", pyDir + ";" + pyScripts + ";" + curPath);
                    Environment.SetEnvironmentVariable("WFT_PYTHON_EXE", pythonExe);
                }
                Environment.SetEnvironmentVariable("WFT_BASE_DIR", baseDir);
            }
            catch { }

            string appDataOverride = Environment.GetEnvironmentVariable("WFT_APPDATA_DIR");
            string appDataWft = !string.IsNullOrWhiteSpace(appDataOverride)
                ? Path.GetFullPath(appDataOverride.Trim())
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WFT");

            bool baseWritable = IsDirectoryWritable(baseDir);
            string primaryMarker = Path.Combine(baseDir, ".wft_setup_done");
            string fallbackMarker = Path.Combine(appDataWft, ".wft_setup_done");
            string activeMarker = baseWritable ? primaryMarker : fallbackMarker;
            bool markerExists = File.Exists(primaryMarker) || (!baseWritable && File.Exists(fallbackMarker));
            bool isFirstRun = forceSetup || !markerExists;

            if (isFirstRun)
            {
                if (!isHeadless)
                {
                    AllocConsole();
                    try { Console.Title = "Windows Forensic Toolkit (WFT) - Initializing Workstation"; } catch { }
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("========================================================================");
                    Console.WriteLine("         WINDOWS FORENSIC TOOLKIT (WFT) - INITIAL SETUP & BOOTSTRAP    ");
                    Console.WriteLine("========================================================================");
                    Console.ResetColor();
                    Console.WriteLine("Working Directory : " + baseDir);
                    Console.WriteLine("Python Engine     : " + pythonExe);
                    Console.WriteLine();
                }

                int pipExit = 0;
                string reqFile = Path.Combine(baseDir, "requirements.txt");
                if (File.Exists(reqFile))
                {
                    if (!isHeadless)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[1/2] Installing required Python dependencies (pip install -r requirements.txt)...");
                        Console.ResetColor();
                    }
                    pipExit = RunProcess(pythonExe, "-m pip install -r \"" + reqFile + "\"", baseDir, isHeadless);
                }

                int psExit = 0;
                string psScript = Path.Combine(baseDir, "Setup-WFTTools.ps1");
                if (!File.Exists(psScript))
                {
                    psExit = 2;
                }
                else if (pipExit == 0)
                {
                    if (!isHeadless)
                    {
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[2/2] Running forensic toolchain auto-installer (Setup-WFTTools.ps1)...");
                        Console.ResetColor();
                    }
                    string trimmedBase = baseDir.TrimEnd('\\');
                    string psArgs = "-NoProfile -ExecutionPolicy Bypass -File \"" + psScript + "\" -ProjectRoot \"" + trimmedBase + "\"";
                    if (!baseWritable)
                    {
                        try { Directory.CreateDirectory(appDataWft); } catch { }
                        string fallbackEnv = Path.Combine(appDataWft, ".env");
                        string fallbackTools = Path.Combine(appDataWft, "tools");
                        psArgs += " -EnvFilePath \"" + fallbackEnv + "\" -ToolsRootDir \"" + fallbackTools + "\"";
                    }
                    string extraPsArgs = Environment.GetEnvironmentVariable("WFT_SETUP_PS_ARGS");
                    if (!string.IsNullOrWhiteSpace(extraPsArgs))
                    {
                        psArgs += " " + extraPsArgs;
                    }
                    string psExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe");
                    if (!File.Exists(psExe)) psExe = "powershell.exe";
                    psExit = RunProcess(psExe, psArgs, baseDir, isHeadless);
                }

                if (pipExit != 0 || psExit != 0)
                {
                    try { if (File.Exists(activeMarker)) File.Delete(activeMarker); } catch { }
                    string errDetail = (pipExit != 0)
                        ? ("Python dependency installation (pip install) failed with exit code " + pipExit + ".")
                        : ("Forensic toolchain bootstrap (Setup-WFTTools.ps1) failed with exit code " + psExit + ".");
                    ShowErrorOrStderr(isHeadless, errDetail, "Windows Forensic Toolkit (WFT) - Setup Failed");
                    if (!isHeadless) FreeConsole();
                    int failCode = (pipExit != 0) ? pipExit : psExit;
                    return (failCode != 0) ? failCode : 1;
                }

                string stamp = "Setup completed at: " + DateTime.UtcNow.ToString("o") + Environment.NewLine;
                bool wroteMarker = false;
                if (baseWritable)
                {
                    try
                    {
                        File.WriteAllText(primaryMarker, stamp);
                        wroteMarker = true;
                    }
                    catch { }
                }
                if (!wroteMarker)
                {
                    try
                    {
                        Directory.CreateDirectory(appDataWft);
                        File.WriteAllText(fallbackMarker, stamp);
                        wroteMarker = true;
                    }
                    catch (Exception ex)
                    {
                        ShowErrorOrStderr(isHeadless, "Failed to persist setup completion marker: " + ex.Message, "WFT Setup Error");
                        if (!isHeadless) FreeConsole();
                        return 1;
                    }
                }

                if (!isHeadless)
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("========================================================================");
                    Console.WriteLine(" [SETUP COMPLETE] Starting Windows Forensic Toolkit Desktop Workstation...");
                    Console.WriteLine("========================================================================");
                    Console.ResetColor();
                    Thread.Sleep(1000);
                    FreeConsole();
                }
            }

            if (setupOnly)
            {
                return 0;
            }

            string launcherPy = Path.Combine(baseDir, "scripts", "wft_launcher.py");
            if (!File.Exists(launcherPy))
            {
                ShowErrorOrStderr(
                    isHeadless,
                    "Launcher script not found: " + launcherPy,
                    "Windows Forensic Toolkit (WFT) - Missing File"
                );
                return 1;
            }

            string forwardArgs = "";
            foreach (var a in passthroughArgs)
            {
                forwardArgs += " \"" + a.Replace("\"", "\\\"") + "\"";
            }

            ProcessStartInfo launchPsi = new ProcessStartInfo();
            launchPsi.FileName = pythonExe;
            launchPsi.Arguments = "\"" + launcherPy + "\"" + forwardArgs;
            launchPsi.WorkingDirectory = baseDir;
            launchPsi.UseShellExecute = false;
            launchPsi.CreateNoWindow = true;

            int targetPort = 8765;
            string portEnv = Environment.GetEnvironmentVariable("WFT_PORT");
            if (!string.IsNullOrWhiteSpace(portEnv))
            {
                int p;
                if (int.TryParse(portEnv.Trim(), out p) && p > 0) targetPort = p;
            }
            for (int i = 0; i < passthroughArgs.Count; i++)
            {
                if (passthroughArgs[i].Equals("--port", StringComparison.OrdinalIgnoreCase) && i + 1 < passthroughArgs.Count)
                {
                    int p;
                    if (int.TryParse(passthroughArgs[i + 1].Trim(), out p) && p > 0) targetPort = p;
                }
                else if (passthroughArgs[i].StartsWith("--port=", StringComparison.OrdinalIgnoreCase))
                {
                    int p;
                    if (int.TryParse(passthroughArgs[i].Substring(7).Trim(), out p) && p > 0) targetPort = p;
                }
            }

            try
            {
                // Delegate desktop window creation and lifecycle tracking to wft_launcher.py
                // so the native WFT desktop shell (or isolated Chrome app window) closes the backend cleanly on exit.
                launchPsi.EnvironmentVariables["WFT_EXIT_ON_UI_CLOSE"] = "1";
            }
            catch { }

            try
            {
                using (Process proc = Process.Start(launchPsi))
                {
                    if (proc != null)
                    {
                        if (isHeadless && passthroughArgs.Count > 0)
                        {
                            proc.WaitForExit();
                            return proc.ExitCode;
                        }

                        // Monitor early initialization (up to 15.0s)
                        // wft_launcher.py opens the native desktop window once services are healthy.
                        // If process crashes during startup, capture exit code and show diagnostic dialog.
                        int waitedMs = 0;
                        const int pollIntervalMs = 150;
                        const int maxWaitMs = 15000;

                        while (waitedMs < maxWaitMs)
                        {
                            if (proc.HasExited)
                            {
                                if (proc.ExitCode != 0)
                                {
                                    string diag = GetRecentLogLines(baseDir, 8);
                                    string msg = "WFT launcher terminated unexpectedly during initialization (exit code " + proc.ExitCode + ").\n\n";
                                    if (!string.IsNullOrWhiteSpace(diag))
                                    {
                                        msg += "Recent Diagnostics:\n" + diag + "\n\n";
                                    }
                                    msg += "Review logs\\wft_runtime.log for diagnostics.";

                                    ShowErrorOrStderr(
                                        isHeadless,
                                        msg,
                                        "Windows Forensic Toolkit (WFT) - Startup Error"
                                    );
                                    return proc.ExitCode;
                                }
                                return 0;
                            }

                            if (IsTcpPortListening(targetPort))
                            {
                                return 0;
                            }

                            Thread.Sleep(pollIntervalMs);
                            waitedMs += pollIntervalMs;
                        }

                        if (!isHeadless && !IsTcpPortListening(targetPort))
                        {
                            string diag = GetRecentLogLines(baseDir, 8);
                            string msg = "WFT is taking longer than expected to initialize.\n\n";
                            if (!string.IsNullOrWhiteSpace(diag))
                            {
                                msg += "Recent Diagnostics:\n" + diag + "\n\n";
                            }
                            msg += "Please review logs\\wft_runtime.log for details.";
                            ShowErrorOrStderr(isHeadless, msg, "Windows Forensic Toolkit (WFT) - Startup Notice");
                        }
                    }
                }
                return 0;
            }
            catch (Exception ex)
            {
                ShowErrorOrStderr(
                    isHeadless,
                    "Failed to launch WFT:\n" + ex.Message,
                    "Windows Forensic Toolkit (WFT) - Launch Error"
                );
                return 1;
            }
        }
    }
}
