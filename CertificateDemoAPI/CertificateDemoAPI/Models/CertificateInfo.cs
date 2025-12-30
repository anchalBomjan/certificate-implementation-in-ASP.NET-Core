namespace CertificateDemoAPI.Models
{
    public class CertificateInfo
    {
        public string Subject { get; set; }
        public string Issuer { get; set; }
        public string Thumbprint { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public bool HasPrivateKey { get; set; }
        public List<string> KeyUsages { get; set; }
        public List<string> EnhancedKeyUsages { get; set; }


    }
}
