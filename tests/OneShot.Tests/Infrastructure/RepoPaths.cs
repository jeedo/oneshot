namespace OneShot.Tests;

internal static class RepoPaths
{
    public static string Root { get; } = Find();

    private static string Find()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "OneShot.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("OneShot.sln not found above the test directory.");
    }
}
