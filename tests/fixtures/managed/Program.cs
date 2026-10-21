namespace EwrParityProbe;

public static class Program
{
    public static string Echo(string value) => "echo:" + value;

    public static async Task<int> Main(string[] args)
    {
        await Task.Yield();
        AppDomain.CurrentDomain.SetData("ewrManagedArgs", args);
        Console.WriteLine("stdout:" + string.Join("|", args));
        Console.Error.WriteLine("stderr:probe");
        if (args.Length > 0 && args[0] == "throw")
            throw new InvalidOperationException("managed-test-error");
        return 42;
    }
}
