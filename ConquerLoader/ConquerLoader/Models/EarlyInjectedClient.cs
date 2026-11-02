using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
        private const string Supported5065Sha256 =
            "97CCC3276D46D46BB91AD62E758D1FB622C036F6224EED5EA7C121A80E550A89";
        private const uint CreateSuspended = 0x00000004;
        private const uint MemCommit = 0x00001000;
        private const uint MemReserve = 0x00002000;
        private const uint MemRelease = 0x00008000;
        private const uint PageReadWrite = 0x04;
        private const uint Synchronize = 0x00100000;
        private const uint WaitObject0 = 0x00000000;

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

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenEvent(uint desiredAccess, bool inheritHandle, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        public static Process Launch(string executablePath, string directory,
            string hookPath, bool requireFlashReady, Action<string> log)
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
            string clientHash;
            using (var stream = File.OpenRead(executablePath))
            using (var sha = SHA256.Create())
                clientHash = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "");
            if (!string.Equals(clientHash, Supported5065Sha256,
                StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException(
                    "Conquer.exe no es el build 5065 soportado. SHA256=" + clientHash +
                    "; esperado=" + Supported5065Sha256 + ". No se inicio ni modifico el cliente.");
            log("Conquer.exe verificado por SHA-256: " + clientHash + ".");
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
                if (requireFlashReady)
                {
                    string readyName = "Local\\ConquerLoader-Flash5065-Ready-" + info.processId;
                    string failedName = "Local\\ConquerLoader-Flash5065-Failed-" + info.processId;
                    IntPtr readyEvent = IntPtr.Zero;
                    IntPtr failedEvent = IntPtr.Zero;
                    bool flashReady = false;
                    watch.Restart();
                    try
                    {
                        while (watch.ElapsedMilliseconds < 12000 && !process.HasExited)
                        {
                            if (readyEvent == IntPtr.Zero)
                                readyEvent = OpenEvent(Synchronize, false, readyName);
                            if (failedEvent == IntPtr.Zero)
                                failedEvent = OpenEvent(Synchronize, false, failedName);
                            if (failedEvent != IntPtr.Zero &&
                                WaitForSingleObject(failedEvent, 0) == WaitObject0)
                                throw new InvalidOperationException(
                                    "La activacion local de Flash fallo. Revisar la ultima etapa y HRESULT en CLHook-5065.log.");
                            if (readyEvent != IntPtr.Zero &&
                                WaitForSingleObject(readyEvent, 0) == WaitObject0)
                            {
                                flashReady = true;
                                break;
                            }
                            Thread.Sleep(50);
                            process.Refresh();
                        }
                    }
                    finally
                    {
                        if (readyEvent != IntPtr.Zero) CloseHandle(readyEvent);
                        if (failedEvent != IntPtr.Zero) CloseHandle(failedEvent);
                    }
                    if (!flashReady)
                        throw new InvalidOperationException(
                            "CLHook.dll cargo, pero Flash.ocx no publico una class factory lista en 12 segundos. " +
                            "Revisar CLHook-5065.log.");
                    log("Flash.ocx local x86 y DllGetClassObject verificados; activacion COM sin registro lista.");
                }
                // A loaded DLL does not mean Conquer.exe reached its main window.
                // Detect immediate fatal exits instead of showing 100% as success.
                for (int i = 0; i < 12; ++i)
                {
                    process.Refresh();
                    if (process.HasExited)
                        throw new InvalidOperationException(
                            "Conquer.exe se cerro tras la carga temprana del hook. ExitCode=0x" +
                            process.ExitCode.ToString("X8") +
                            ". Revisar CLHook-5065.log.");
                    Thread.Sleep(100);
                }
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
