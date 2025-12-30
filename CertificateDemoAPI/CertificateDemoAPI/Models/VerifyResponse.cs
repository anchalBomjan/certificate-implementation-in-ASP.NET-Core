namespace CertificateDemoAPI.Models
{
    public class VerifyResponse
    {

        public bool IsValid { get; set; }
        public string Message { get; set; }
        public DateTime VerificationTime { get; set; }
        public string VerifiedBy { get; set; }
        public string Algorithm { get; set; }
    }
}
