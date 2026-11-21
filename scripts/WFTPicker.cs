using System;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace WFTPicker
{
    class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            try { Console.OutputEncoding = Encoding.UTF8; } catch { }
            if (args == null) args = new string[0];

            if (args.Length > 0 && args[0].Equals("--test", StringComparison.OrdinalIgnoreCase))
            {
                Console.Out.WriteLine("WFT_PICKER_OK");
                return 0;
            }

            try
            {
                Application.EnableVisualStyles();
                string mode = (args.Length > 0 && !string.IsNullOrEmpty(args[0])) ? args[0].ToLowerInvariant() : "folder";
                string title = (args.Length > 1 && !string.IsNullOrEmpty(args[1])) ? args[1] : (mode == "file" ? "Select Forensic Image or File" : "Select Target Directory");
                string initDir = (args.Length > 2 && !string.IsNullOrEmpty(args[2])) ? args[2] : "";

                using (Form f = new Form())
                {
                    f.TopMost = true;
                    f.ShowInTaskbar = false;
                    f.Opacity = 0;
                    if (mode == "file")
                    {
                        using (OpenFileDialog ofd = new OpenFileDialog())
                        {
                            ofd.Title = title;
                            if (!string.IsNullOrEmpty(initDir) && Directory.Exists(initDir))
                            {
                                ofd.InitialDirectory = initDir;
                            }
                            ofd.Filter = "Forensic Disk Images (*.E01;*.Ex01;*.VHDX;*.VHD;*.VMDK;*.RAW;*.DD;*.IMG;*.ISO;*.001)|*.E01;*.Ex01;*.e01;*.vhdx;*.vhd;*.vmdk;*.raw;*.dd;*.img;*.iso;*.001|Forensic Archives & Logs (*.zip;*.7z;*.rar;*.tar;*.gz;*.evtx;*.hve;*.db)|*.zip;*.7z;*.rar;*.tar;*.gz;*.evtx;*.hve;*.db|All Files (*.*)|*.*";
                            ofd.RestoreDirectory = true;
                            if (ofd.ShowDialog(f) == DialogResult.OK)
                            {
                                Console.Out.WriteLine(ofd.FileName);
                                return 0;
                            }
                            return 1;
                        }
                    }
                    else
                    {
                        using (FolderBrowserDialog fbd = new FolderBrowserDialog())
                        {
                            fbd.Description = title;
                            fbd.ShowNewFolderButton = true;
                            if (!string.IsNullOrEmpty(initDir) && Directory.Exists(initDir))
                            {
                                fbd.SelectedPath = initDir;
                            }
                            if (fbd.ShowDialog(f) == DialogResult.OK)
                            {
                                Console.Out.WriteLine(fbd.SelectedPath);
                                return 0;
                            }
                            return 1;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 2;
            }
        }
    }
}
