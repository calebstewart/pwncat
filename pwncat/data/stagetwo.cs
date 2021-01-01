class StageTwo
{
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
}
