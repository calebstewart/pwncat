using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

class StageTwo
{

    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint ENABLE_WRAP_AT_EOL_OUTPUT = 0x0002;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int BUFFER_SIZE_PIPE = 1048576;

    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const int SW_HIDE = 0;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = 3;
    private const uint OPEN_ALWAYS = 4;
    private const uint TRUNCATE_EXISTING = 5;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X;
        public short Y;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcess, IntPtr hSource, IntPtr hTargetProcess, out IntPtr lpTarget, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CancelSynchronousIo(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out UInt32 lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern bool FlushFileBuffers(IntPtr hFile);

    private System.Collections.Generic.List<System.Diagnostics.Process> g_processes;

    public System.String ReadUntilLine(System.String delimeter)
    {
        System.Text.StringBuilder builder = new System.Text.StringBuilder();

        while (true)
        {
            System.String line = System.Console.ReadLine();
            if (line == delimeter)
            {
                break;
            }
            builder.AppendLine(line);
        }

        return builder.ToString();
    }

    public void main()
    {
        object[] args = new object[] { };

        System.Console.WriteLine("READY");

        while (true)
        {
            System.String line = System.Console.ReadLine();
            var method = GetType().GetMethod(line);
            if (method == null) continue;
            method.Invoke(this, args);
        }
    }

    public void process()
    {
        IntPtr stdin_read, stdin_write;
        IntPtr stdout_read, stdout_write;
        IntPtr stderr_read, stderr_write;
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        STARTUPINFO pInfo = new STARTUPINFO();
        PROCESS_INFORMATION childInfo = new PROCESS_INFORMATION();
        System.String command = System.Console.ReadLine();

        pSec.nLength = Marshal.SizeOf(pSec);
        pSec.bInheritHandle = 1;
        pSec.lpSecurityDescriptor = IntPtr.Zero;

        if (!CreatePipe(out stdin_read, out stdin_write, ref pSec, BUFFER_SIZE_PIPE))
        {
            System.Console.WriteLine("E:IN");
            return;
        }

        if (!CreatePipe(out stdout_read, out stdout_write, ref pSec, BUFFER_SIZE_PIPE))
        {
            System.Console.WriteLine("E:OUT");
            return;
        }

        if (!CreatePipe(out stderr_read, out stderr_write, ref pSec, BUFFER_SIZE_PIPE))
        {
            System.Console.WriteLine("E:ERR");
            return;
        }

        pInfo.cb = Marshal.SizeOf(pInfo);
        pInfo.hStdError = stderr_write;
        pInfo.hStdOutput = stdout_write;
        pInfo.hStdInput = stdin_read;
        pInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;

        if (!CreateProcessW(null, command, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref pInfo, out childInfo))
        {
            System.Console.WriteLine("E:PROC");
            return;
        }

        CloseHandle(stdin_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);

        System.Console.WriteLine(childInfo.hProcess);
        System.Console.WriteLine(stdin_write);
        System.Console.WriteLine(stdout_read);
        System.Console.WriteLine(stderr_read);
    }

    public void ppoll()
    {
        IntPtr hProcess = new IntPtr(System.UInt32.Parse(System.Console.ReadLine()));
        System.UInt32 result = WaitForSingleObject(hProcess, 0);

        if (result == 0x00000102L)
        {
            System.Console.WriteLine("R");
            return;
        }
        else if (result == 0xFFFFFFFF)
        {
            System.Console.WriteLine("E");
            return;
        }

        if (!GetExitCodeProcess(hProcess, out result))
        {
            System.Console.WriteLine("E");
        }

        System.Console.WriteLine(result);
    }

    public void kill()
    {
        IntPtr hProcess = new IntPtr(System.UInt32.Parse(System.Console.ReadLine()));
        UInt32 code = System.UInt32.Parse(System.Console.ReadLine());
        TerminateProcess(hProcess, code);
    }

    public void open()
    {
        System.String filename = System.Console.ReadLine();
        System.String mode = System.Console.ReadLine();
        uint desired_access = GENERIC_READ;
        uint creation_disposition = OPEN_EXISTING;
        IntPtr handle;

        if (mode.Contains("r"))
        {
            desired_access |= GENERIC_READ;
        }
        if (mode.Contains("w"))
        {
            desired_access |= GENERIC_WRITE;
            creation_disposition = TRUNCATE_EXISTING;
        }

        handle = CreateFile(filename, desired_access, 0, IntPtr.Zero, creation_disposition, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);

        if (handle == (new IntPtr(-1)))
        {
            int error = Marshal.GetLastWin32Error();
            System.Console.Write("E:");
            System.Console.WriteLine(error);
            return;
        }

        System.Console.WriteLine(handle);
    }

    public void read()
    {
        System.String line;
        IntPtr handle;
        uint count;
        uint nreceived;

        line = System.Console.ReadLine();
        handle = new IntPtr(System.UInt32.Parse(line));
        line = System.Console.ReadLine();
        count = System.UInt32.Parse(line);

        byte[] buffer = new byte[count];

        if (!ReadFile(handle, buffer, count, out nreceived, IntPtr.Zero))
        {
            System.Console.WriteLine("0");
            return;
        }

        System.Console.WriteLine(nreceived);

        using (Stream out_stream = System.Console.OpenStandardOutput())
        {
            out_stream.Write(buffer, 0, (int)nreceived);
        }

        return;
    }

    public void write()
    {
        System.String line;
        IntPtr handle;
        uint count;
        uint nwritten;

        line = System.Console.ReadLine();
        handle = new IntPtr(System.UInt32.Parse(line));
        line = System.Console.ReadLine();
        count = System.UInt32.Parse(line);

        byte[] buffer = new byte[count];

        using (Stream in_stream = System.Console.OpenStandardInput())
        {
            count = (uint)in_stream.Read(buffer, 0, (int)count);
        }

        if (!WriteFile(handle, buffer, count, out nwritten, IntPtr.Zero))
        {
            System.Console.WriteLine("0");
            return;
        }

        System.Console.WriteLine(nwritten);
        return;
    }

    public void close()
    {
        IntPtr handle = new IntPtr(System.UInt32.Parse(System.Console.ReadLine()));
        CloseHandle(handle);
    }

    public void powershell()
    {
        var command = System.Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ReadUntilLine("# ENDBLOCK")));
        var startinfo = new System.Diagnostics.ProcessStartInfo()
        {
            FileName = "powershell.exe",
            Arguments = "-noprofile -ep unrestricted -enc " + command,
            UseShellExecute = false
        };

        var p = System.Diagnostics.Process.Start(startinfo);
        p.WaitForExit();
    }

    public void csharp()
    {
        var cp = new System.CodeDom.Compiler.CompilerParameters()
        {
            GenerateExecutable = false,
            GenerateInMemory = true,
        };

        while (true)
        {
            System.String line = System.Console.ReadLine();
            if (line == "/* ENDASM */") break;
            cp.ReferencedAssemblies.Add(line);
        }

        cp.ReferencedAssemblies.Add("System.dll");
        cp.ReferencedAssemblies.Add("System.Core.dll");
        cp.ReferencedAssemblies.Add("System.Dynamic.dll");
        cp.ReferencedAssemblies.Add("Microsoft.CSharp.dll");

        var r = new Microsoft.CSharp.CSharpCodeProvider().CompileAssemblyFromSource(cp, ReadUntilLine("/* ENDBLOCK */"));
        if (r.Errors.HasErrors)
        {
            return;
        }

        var obj = r.CompiledAssembly.CreateInstance("command");
        obj.GetType().GetMethod("main").Invoke(obj, new object[] { });
    }

    public void interactive()
    {
        uint result;
        IntPtr stdin_read = new IntPtr(0), stdin_write = new IntPtr(0);
        IntPtr stdout_read = new IntPtr(0), stdout_write = new IntPtr(0);
        UInt32 rows = System.UInt32.Parse(System.Console.ReadLine());
        UInt32 cols = System.UInt32.Parse(System.Console.ReadLine());
        COORD pty_size = new COORD()
        {
            X = (short)cols,
            Y = (short)rows
        };
        IntPtr hpcon = new IntPtr(0);
        uint conmode = 0;
        IntPtr old_stdin = GetStdHandle(STD_INPUT_HANDLE),
            old_stdout = GetStdHandle(STD_OUTPUT_HANDLE),
            old_stderr = GetStdHandle(STD_ERROR_HANDLE);
        IntPtr stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        IntPtr stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES proc_attr = new SECURITY_ATTRIBUTES();
        SECURITY_ATTRIBUTES thread_attr = new SECURITY_ATTRIBUTES();
        SECURITY_ATTRIBUTES pipe_attr = new SECURITY_ATTRIBUTES()
        {
            bInheritHandle = 1,
            lpSecurityDescriptor = IntPtr.Zero,
        };
        STARTUPINFOEX startup_info = new STARTUPINFOEX();
        IntPtr lpSize = IntPtr.Zero;
        Thread stdin_thread;
        Thread stdout_thread;
        bool new_console = false;

        proc_attr.nLength = Marshal.SizeOf(proc_attr);
        thread_attr.nLength = Marshal.SizeOf(thread_attr);
        pipe_attr.nLength = Marshal.SizeOf(pipe_attr);

        stdout_handle = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        stdin_handle = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        SetStdHandle(STD_INPUT_HANDLE, stdin_handle);
        SetStdHandle(STD_ERROR_HANDLE, stdout_handle);
        SetStdHandle(STD_OUTPUT_HANDLE, stdout_handle);

        GetConsoleMode(stdout_handle, out conmode);
        uint new_conmode = conmode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        SetConsoleMode(stdout_handle, new_conmode);

        CreatePipe(out stdin_read, out stdin_write, ref pipe_attr, 8192);
        CreatePipe(out stdout_read, out stdout_write, ref pipe_attr, 8192);
        CreatePseudoConsole(pty_size, stdin_read, stdout_write, 0, out hpcon);
        CloseHandle(stdin_read);
        CloseHandle(stdout_write);

        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        startup_info.StartupInfo.cb = Marshal.SizeOf(startup_info);
        startup_info.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        InitializeProcThreadAttributeList(startup_info.lpAttributeList, 1, 0, ref lpSize);
        UpdateProcThreadAttribute(startup_info.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, hpcon, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

        CreateProcess(null, "powershell.exe", ref proc_attr, ref thread_attr, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref startup_info, out proc_info);

        stdin_thread = new Thread(pipe_thread);
        stdin_thread.Start(new object[] { old_stdin, stdin_write, "stdin" });
        stdout_thread = new Thread(pipe_thread);
        stdout_thread.Start(new object[] { stdout_read, old_stdout, "stdout" });

        WaitForSingleObject(proc_info.hProcess, INFINITE);

        stdin_thread.Abort();
        stdout_thread.Abort();

        CloseHandle(proc_info.hThread);
        CloseHandle(proc_info.hProcess);
        ClosePseudoConsole(hpcon);
        CloseHandle(stdin_write);
        CloseHandle(stdout_read);

        SetStdHandle(STD_INPUT_HANDLE, old_stdin);
        SetStdHandle(STD_ERROR_HANDLE, old_stderr);
        SetStdHandle(STD_OUTPUT_HANDLE, old_stdout);

        CloseHandle(stdout_handle);
        CloseHandle(stdin_handle);

        System.Console.WriteLine("");
        System.Console.WriteLine("INTERACTIVE_COMPLETE");
    }

    private void pipe_thread(object dumb)
    {
        object[] parms = (object[])dumb;
        IntPtr read = (IntPtr)parms[0];
        IntPtr write = (IntPtr)parms[1];
        String name = (String)parms[2];
        uint bufsz = 16 * 1024;
        byte[] bytes = new byte[bufsz];
        bool read_success = false;
        uint nsent = 0;
        uint nread = 0;

        try {
            do
            {
                read_success = ReadFile(read, bytes, bufsz, out nread, IntPtr.Zero);
                WriteFile(write, bytes, nread, out nsent, IntPtr.Zero);
                FlushFileBuffers(write);
            } while (nsent > 0 && read_success);
        } finally {
        }
    }
}
