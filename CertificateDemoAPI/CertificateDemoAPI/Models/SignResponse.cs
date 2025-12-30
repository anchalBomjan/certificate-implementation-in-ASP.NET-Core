namespace CertificateDemoAPI.Models
{
    public class SignResponse
    {
        public bool Success { get; set; }
        public string Signature { get; set; }
        public string DocumentHash { get; set; }
        public string SignedBy { get; set; }
        public DateTime Timestamp { get; set; }
        public string CertificateThumbprint { get; set; }
        public string Algorithm { get; set; }

    }
}
