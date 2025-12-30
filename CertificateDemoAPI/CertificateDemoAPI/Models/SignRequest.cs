namespace CertificateDemoAPI.Models
{
    public class SignRequest
    {

        public string DocumentBase64 { get; set; }
        public string Algorithm { get; set; } = "SHA256";
    }
}
