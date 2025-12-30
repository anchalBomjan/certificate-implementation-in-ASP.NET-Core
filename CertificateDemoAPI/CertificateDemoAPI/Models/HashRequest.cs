namespace CertificateDemoAPI.Models
{
    public class HashRequest
    {
        public string HashBase64 { get; set; }
        public string Algorithm { get; set; } = "SHA256";
    }
}
