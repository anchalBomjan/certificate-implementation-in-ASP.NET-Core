namespace CertificateDemoAPI.Models
{
    public class VerifyRequest
    {

        public string DocumentBase64 { get; set; }
        public string Signature { get; set; }
        public string CertificateBase64 { get; set; }
    }
}
