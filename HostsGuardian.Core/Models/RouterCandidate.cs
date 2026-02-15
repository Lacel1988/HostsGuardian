namespace HostsGuardian.Wpf.Models
{
    public sealed class RouterCandidate
    {
        public string Name { get; set; } = "";
        public int Confidence { get; set; } = 0; // 0..100
        public string Evidence { get; set; } = "";
    }
}
