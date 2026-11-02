using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace ConquerLoader.Models
{
    /// <summary>
    /// Dragon-inspired 5065 startup: queue the legacy CLHook onto the primary thread
    /// while Conquer.exe is CREATE_SUSPENDED. The old launcher injected too late,
    /// after Conquer had already attempted to initialize ActiveX Flash.
    /// This class neither registers OCX files nor modifies Conquer.exe on disk.
    /// </summary>
    internal static class EarlyInjectedClient
    {
        private const uint CreateSuspended = 0x00000004;
        private const uint MemCommit = 0x00001000;
        private const uint MemReserve = 0x00002000;
        private const uint MemRelease = 0x00008000;
        private const uint PageReadWrite = 0x04;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct StartupInfo
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ProcessInformation
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int processId;
            public int threadId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
            uint creationFlags, IntPtr environment, string currentDirectory,
            ref StartupInfo startupInfo, out ProcessInformation processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address,
            UIntPtr size, uint allocationType, uint protection);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr process, IntPtr address,
            byte[] buffer, UIntPtr length, out UIntPtr written);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr process, IntPtr address,
            UIntPtr size, uint freeType);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string name);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr procedure, IntPtr thread, UIntPtr data);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint code);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        public static Process Launch(string executablePath, string directory,
            string hookPath, Action<string> log)
        {
            if (IntPtr.Size != 4)
                throw new InvalidOperationException("La inyeccion inicial exige ConquerLoader x86.");
            if (!File.Exists(executablePath))
                throw new FileNotFoundException("Conquer.exe no existe.", executablePath);
            if (!File.Exists(hookPath))
                throw new FileNotFoundException("No se encontro CLHook.dll actualizado.", hookPath);

            executablePath = Path.GetFullPath(executablePath);
            hookPath = Path.GetFullPath(hookPath);
            directory = Path.GetFullPath(directory);
            var startup = new StartupInfo { cb = Marshal.SizeOf(typeof(StartupInfo)) };
            ProcessInformation info;
            var command = new StringBuilder("\"" + executablePath + "\" blacknull");
            if (!CreateProcessW(executablePath, command, IntPtr.Zero, IntPtr.Zero,
                false, CreateSuspended, IntPtr.Zero, directory, ref startup, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo iniciar Conquer.exe suspendido.");

            IntPtr remote = IntPtr.Zero;
            bool started = false;
            try
            {
                // Unicode path is NUL-terminated; buffer must survive until APC executes.
                byte[] bytes = Encoding.Unicode.GetBytes(hookPath + "\0");
                remote = VirtualAllocEx(info.hProcess, IntPtr.Zero,
                    (UIntPtr)bytes.Length, MemCommit | MemReserve, PageReadWrite);
                if (remote == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo reservar memoria para CLHook.");
                UIntPtr written;
                if (!WriteProcessMemory(info.hProcess, remote, bytes,
                    (UIntPtr)bytes.Length, out written) ||
                    written.ToUInt64() != (ulong)bytes.Length)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo preparar la ruta del hook.");

                IntPtr kernel = GetModuleHandle("kernel32.dll");
                IntPtr loadLibrary = kernel == IntPtr.Zero ? IntPtr.Zero :
                    GetProcAddress(kernel, "LoadLibraryW");
                if (loadLibrary == IntPtr.Zero)
                    throw new InvalidOperationException("No se encontro LoadLibraryW (x86).");
                if (QueueUserAPC(loadLibrary, info.hThread, (UIntPtr)remote.ToInt32()) == 0)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo programar CLHook antes del inicio.");

                log("CLHook preparado por APC con Conquer.exe suspendido (metodo Dragon).");
                if (ResumeThread(info.hThread) == 0xffffffff)
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "No se pudo reanudar Conquer.exe.");

                // Don't report success merely because QueueUserAPC succeeded. Confirm
                // the DLL is actually present in the client process before releasing
                // its remote pathname buffer. No re-injection is performed here.
                Process process = Process.GetProcessById(info.processId);
                var watch = Stopwatch.StartNew();
                bool found = false;
                while (watch.ElapsedMilliseconds < 12000 && !process.HasExited)
                {
                    try
                    {
                        process.Refresh();
                        foreach (ProcessModule module in process.Modules)
                        {
                            if (string.Equals(module.ModuleName, "CLHook.dll",
                                StringComparison.OrdinalIgnoreCase))
                            {
                                found = true;
                                break;
                            }
                        }
                    }
                    catch (Win32Exception) { }
                    catch (InvalidOperationException) { break; }
                    if (found) break;
                    Thread.Sleep(80);
                }
                if (!found)
                    throw new InvalidOperationException(
                        "La inyeccion APC no cargo CLHook.dll antes de iniciar el juego; se cancelo la prueba.");

                log("CLHook.dll confirmado dentro de Conquer.exe; inicio temprano completado.");
                started = true;
                return process;
            }
            finally
            {
                if (!started)
                {
                    TerminateProcess(info.hProcess, 1);
                    log("Fallo el inicio temprano. Proceso de prueba detenido para evitar ejecucion sin hook.");
                }
                if (remote != IntPtr.Zero)
                    VirtualFreeEx(info.hProcess, remote, UIntPtr.Zero, MemRelease);
                if (info.hThread != IntPtr.Zero) CloseHandle(info.hThread);
                if (info.hProcess != IntPtr.Zero) CloseHandle(info.hProcess);
            }
        }
    }
}
