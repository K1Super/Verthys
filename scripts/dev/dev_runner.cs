// scripts/dev/dev_runner.cs - cargo target runner shim for the signed dev host
//
// Cargo invokes this executable with the freshly built host path followed by
// application arguments. The shim starts the PowerShell launcher (which signs
// and stages the host) inside a kill-on-close job object, and terminates the
// launcher when cargo disappears so the Tauri watcher cannot leave orphaned
// processes behind.
//
// ASCII only.

using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Threading;

public static class VerthysDevRunner
{
    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr info, uint infoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
    private static Process activeChild;

    public static int Main(string[] args)
    {
        try
        {
            if (args == null || args.Length < 1)
            {
                Console.Error.WriteLine("dev_runner: missing built host path");
                return 2;
            }

            string repoRoot = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, ".."));
            string launcher = Path.Combine(repoRoot, "scripts", "dev", "dev_app_launcher.ps1");
            string powershell = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe");
            if (!File.Exists(launcher))
            {
                Console.Error.WriteLine("dev_runner: launcher missing: " + launcher);
                return 2;
            }
            if (!File.Exists(powershell))
            {
                Console.Error.WriteLine("dev_runner: powershell missing: " + powershell);
                return 2;
            }

            string commandLine = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(launcher);
            for (int i = 0; i < args.Length; i++)
            {
                commandLine += " " + Quote(args[i]);
            }

            var startInfo = new ProcessStartInfo(powershell, commandLine);
            startInfo.UseShellExecute = false;
            startInfo.WorkingDirectory = Path.Combine(repoRoot, "verthys-tauri", "src-tauri");
            Process child = Process.Start(startInfo);
            if (child == null)
            {
                Console.Error.WriteLine("dev_runner: failed to start the dev launcher");
                return 2;
            }
            activeChild = child;
            Console.CancelKeyPress += (sender, eventArgs) =>
            {
                eventArgs.Cancel = true;
                try
                {
                    if (activeChild != null && !activeChild.HasExited)
                    {
                        activeChild.Kill();
                    }
                }
                catch
                {
                }
            };

            IntPtr job = CreateKillOnCloseJob();
            if (job != IntPtr.Zero)
            {
                try
                {
                    AssignProcessToJobObject(job, child.Handle);
                }
                catch
                {
                }
            }

            int parentPid = GetParentProcessId();
            while (!child.HasExited)
            {
                if (parentPid > 0 && !IsProcessAlive(parentPid))
                {
                    try
                    {
                        child.Kill();
                    }
                    catch
                    {
                    }
                    break;
                }
                Thread.Sleep(500);
            }

            child.WaitForExit();
            int exitCode = child.ExitCode;
            if (job != IntPtr.Zero)
            {
                CloseHandle(job);
            }
            return exitCode;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("dev_runner: " + error.Message);
            return 2;
        }
    }

    private static string Quote(string value)
    {
        if (value == null)
        {
            return "\"\"";
        }
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private static int GetParentProcessId()
    {
        try
        {
            using (var searcher = new ManagementObjectSearcher(
                "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = " + Process.GetCurrentProcess().Id))
            {
                foreach (ManagementObject item in searcher.Get())
                {
                    object value = item["ParentProcessId"];
                    if (value != null)
                    {
                        return Convert.ToInt32(value);
                    }
                }
            }
        }
        catch
        {
        }
        return 0;
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using (Process process = Process.GetProcessById(pid))
            {
                return !process.HasExited;
            }
        }
        catch
        {
            return false;
        }
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            if (!SetInformationJobObject(job, 9, buffer, (uint)length))
            {
                CloseHandle(job);
                return IntPtr.Zero;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return job;
    }
}
