using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.Threading;

namespace WFTLauncher
{
    static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;
        const int SW_SHOW = 5;

        [STAThread]
        static void Main(string[] args)
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            Environment.CurrentDirectory = baseDir;

            string pythonExe = ResolvePython();
            if (string.IsNullOrEmpty(pythonExe))
            {
                MessageBox.Show(
                    "Python 3.10+ was not found on your system PATH or standard installation directories.\n\n" +
                    "Please install Python 3.10, 3.11, or 3.12 from https://www.python.org\n" +
                    "and ensure the checkbox 'Add Python to PATH' is selected during installation.",
                    "Windows Forensic Toolkit (WFT) - Python Prerequisite Missing",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return;
            }

            string markerPath = Path.Combine(baseDir, ".wft_setup_done");
            bool isFirstRun = !File.Exists(markerPath);

            // If user passed --setup or --reinstall flag, force first-run setup
            if (args != null && args.Length > 0)
            {
                foreach (var arg in args)
                {
                    if (arg.Equals("--setup", StringComparison.OrdinalIgnoreCase) ||
                        arg.Equals("/setup", StringComparison.OrdinalIgnoreCase) ||
                        arg.Equals("--reinstall", StringComparison.OrdinalIgnoreCase))
                    {
                        isFirstRun = true;
                        break;
                    }
                }
            }

            if (isFirstRun)
            {
                AllocConsole();
                Console.Title = "Windows Forensic Toolkit (WFT) - Initializing Workstation";
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("========================================================================");
                Console.WriteLine("         WINDOWS FORENSIC TOOLKIT (WFT) - INITIAL SETUP & BOOTSTRAP    ");
                Console.WriteLine("========================================================================");
                Console.ResetColor();
                Console.WriteLine("Welcome! This one-time setup configures Python dependencies and");
                Console.WriteLine("external forensic tools. Subsequent launches will start immediately.");
                Console.WriteLine();
                Console.WriteLine("Working Directory : " + baseDir);
                Console.WriteLine("Python Engine     : " + pythonExe);
                Console.WriteLine();

                // 1. Install Requirements
                string reqFile = Path.Combine(baseDir, "requirements.txt");
                if (File.Exists(reqFile))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[1/2] Installing required Python dependencies (pip install -r requirements.txt)...");
                    Console.ResetColor();

                    int pipExit = RunProcessVisible(pythonExe, "-m pip install -r \"" + reqFile + "\"");
                    if (pipExit != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine();
                        Console.WriteLine("[WARNING] pip install exited with code " + pipExit + ". Continuing setup...");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[✓] Python dependencies verified and ready.");
                        Console.ResetColor();
                    }
                }

                Console.WriteLine();

                // 2. Run Setup-WFTTools.ps1
                string psScript = Path.Combine(baseDir, "Setup-WFTTools.ps1");
                if (File.Exists(psScript))
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("[2/2] Running forensic toolchain auto-installer (Setup-WFTTools.ps1)...");
                    Console.ResetColor();

                    string psArgs = "-NoProfile -ExecutionPolicy Bypass -File \"" + psScript + "\"";
                    int psExit = RunProcessVisible("powershell.exe", psArgs);
                    if (psExit != 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine();
                        Console.WriteLine("[NOTICE] Setup-WFTTools.ps1 completed with code " + psExit + ".");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[✓] Forensic toolchain verified and configured.");
                        Console.ResetColor();
                    }
                }

                // 3. Mark setup done
                try
                {
                    File.WriteAllText(markerPath, "Setup completed at: " + DateTime.UtcNow.ToString("o"));
                }
                catch { }

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("========================================================================");
                Console.WriteLine(" [SETUP COMPLETE] Starting Windows Forensic Toolkit Desktop Workstation...");
                Console.WriteLine("========================================================================");
                Console.ResetColor();
                Thread.Sleep(2000);
                FreeConsole();
            }

            // Launch scripts/wft_launcher.py
            string launcherPy = Path.Combine(baseDir, "scripts", "wft_launcher.py");
            if (!File.Exists(launcherPy))
            {
                MessageBox.Show(
                    "Launcher script not found: " + launcherPy,
                    "Windows Forensic Toolkit (WFT) - Missing File",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return;
            }

            // Run launcher windowless
            string forwardArgs = "";
            if (args != null && args.Length > 0)
            {
                foreach (var a in args)
                {
                    if (!a.Equals("--setup", StringComparison.OrdinalIgnoreCase) &&
                        !a.Equals("/setup", StringComparison.OrdinalIgnoreCase) &&
                        !a.Equals("--reinstall", StringComparison.OrdinalIgnoreCase))
                    {
                        forwardArgs += " \"" + a.Replace("\"", "\\\"") + "\"";
                    }
                }
            }

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = pythonExe;
            psi.Arguments = "\"" + launcherPy + "\"" + forwardArgs;
            psi.WorkingDirectory = baseDir;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;

            try
            {
                Process.Start(psi);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Failed to launch WFT:\n" + ex.Message,
                    "Windows Forensic Toolkit (WFT) - Launch Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }

        static int RunProcessVisible(string fileName, string arguments)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = fileName;
            psi.Arguments = arguments;
            psi.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
            psi.UseShellExecute = false;
            psi.CreateNoWindow = false;

            try
            {
                using (Process proc = Process.Start(psi))
                {
                    proc.WaitForExit();
                    return proc.ExitCode;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to run " + fileName + ": " + ex.Message);
                return -1;
            }
        }

        static string ResolvePython()
        {
            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            string[] dirs = pathEnv.Split(';');
            foreach (var d in dirs)
            {
                if (string.IsNullOrWhiteSpace(d)) continue;
                try
                {
                    string candidate = Path.Combine(d.Trim(), "python.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }

            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string[] common = new string[] {
                Path.Combine(localAppData, @"Programs\Python\Python312\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python311\python.exe"),
                Path.Combine(localAppData, @"Programs\Python\Python310\python.exe"),
                Path.Combine(localAppData, @"Microsoft\WindowsApps\python.exe"),
                @"C:\Python312\python.exe",
                @"C:\Python311\python.exe",
                @"C:\Python310\python.exe"
            };
            foreach (var cand in common)
            {
                if (File.Exists(cand)) return cand;
            }

            return null;
        }
    }
}
