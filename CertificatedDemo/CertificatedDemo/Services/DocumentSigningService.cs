using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertificatedDemo.Services;

public class DocumentSigningService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<DocumentSigningService> _logger;

    public DocumentSigningService(IConfiguration configuration, ILogger<DocumentSigningService> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public SigningResult SignDocument(string content, string? certificatePath = null, string? password = null)
    {
        try
        {
            var certPath = certificatePath ?? "certificates/doc.pfx";
            var certPassword = password ?? "DocPass123!";

            if (string.IsNullOrEmpty(certPath) || !File.Exists(certPath))
                throw new FileNotFoundException("Document signing certificate not found", certPath);

            using var cert = new X509Certificate2(certPath, certPassword);
            using var rsa = cert.GetRSAPrivateKey();

            if (rsa == null)
                throw new InvalidOperationException("Certificate does not have private key for signing");

            var contentBytes = Encoding.UTF8.GetBytes(content);
            var hash = SHA256.HashData(contentBytes);
            var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Create timestamp
            var timestamp = DateTime.UtcNow;
            var timestampBytes = Encoding.UTF8.GetBytes(timestamp.ToString("O"));
            var timestampHash = SHA256.HashData(timestampBytes);
            var timestampSignature = rsa.SignHash(timestampHash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return new SigningResult
            {
                Success = true,
                OriginalContent = content,
                ContentHash = Convert.ToBase64String(hash),
                Signature = Convert.ToBase64String(signature),
                Timestamp = timestamp,
                TimestampSignature = Convert.ToBase64String(timestampSignature),
                Certificate = new CertificateInfo
                {
                    Subject = cert.Subject,
                    Thumbprint = cert.Thumbprint,
                    Issuer = cert.Issuer,
                    ValidFrom = cert.NotBefore,
                    ValidTo = cert.NotAfter
                },
                SignatureAlgorithm = "SHA256withRSA",
                SignatureLength = signature.Length
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Document signing failed");
            return new SigningResult
            {
                Success = false,
                Error = ex.Message
            };
        }
    }

    public bool VerifyDocumentSignature(string content, string signature, X509Certificate2 certificate)
    {
        try
        {
            using var rsa = certificate.GetRSAPublicKey();
            if (rsa == null)
                return false;

            var contentBytes = Encoding.UTF8.GetBytes(content);
            var hash = SHA256.HashData(contentBytes);
            var signatureBytes = Convert.FromBase64String(signature);

            return rsa.VerifyHash(hash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
        catch
        {
            return false;
        }
    }

    public bool VerifyDocumentSignature(string content, string signature, string certificatePath, string? password = null)
    {
        try
        {
            using var cert = new X509Certificate2(certificatePath, password);
            return VerifyDocumentSignature(content, signature, cert);
        }
        catch
        {
            return false;
        }
    }
}

public class SigningResult
{
    public bool Success { get; set; }
    public string? Error { get; set; }
    public string OriginalContent { get; set; } = string.Empty;
    public string ContentHash { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string TimestampSignature { get; set; } = string.Empty;
    public CertificateInfo Certificate { get; set; } = new();
    public string SignatureAlgorithm { get; set; } = string.Empty;
    public int SignatureLength { get; set; }
}

public class CertificateInfo
{
    public string Subject { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime ValidFrom { get; set; }
    public DateTime ValidTo { get; set; }
}