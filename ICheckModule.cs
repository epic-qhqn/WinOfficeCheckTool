namespace WinCheckTool
{
    // Defines standard exit statuses for inspection modules.
    public enum CheckStatus 
    { 
        Clean,      // Genuine / Safe state
        Warning,    // Suspicious / Mismatched / Incomplete activation
        Danger,     // Crack or bypass mechanism detected
        Error       // Exception occurred during scanning
    }

    // Encapsulates the execution outcome of a forensic module.
    public class CheckResult
    {
        public CheckStatus Status { get; set; }
        public string Message { get; set; }
    }

    // Core interface architecture for modular execution.
    public interface ICheckModule
    {
        string ModuleName { get; }
        CheckResult Execute();
    }
}