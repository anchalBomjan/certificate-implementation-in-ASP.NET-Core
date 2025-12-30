using CertificateDemoAPI.Models;
using CertificateDemoAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace CertificateDemoAPI.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class DocumentController : ControllerBase
    {
        private readonly IDigitalSignatureService _signatureService;
        private readonly ICertificateValidationService _certificateValidationService;
        private readonly ILogger<DocumentController> _logger;

        public DocumentController(
            IDigitalSignatureService signatureService,
            ICertificateValidationService certificateValidationService,
            ILogger<DocumentController> logger)
        {
            _signatureService = signatureService;
            _certificateValidationService = certificateValidationService;
            _logger = logger;
        }

        [HttpPost("sign")]
        [Authorize(AuthenticationSchemes = "Certificate")]
        public IActionResult SignDocument([FromBody] SignRequest request)
        {
            try
            {
                //var clientCert = HttpConnectionExtensions.GetClientCertificate(HttpContext);
                var clientCert = HttpContext.Connection.ClientCertificate;

                if (clientCert == null || !clientCert.HasPrivateKey)
                {
                    return Unauthorized(new
                    {
                        Message = "Valid client certificate with private key required for signing"
                    });
                }

                // Validate certificate
                var validationResult = _certificateValidationService.ValidateCertificateWithDetails(clientCert);
                if (!validationResult.IsValid)
                {
                    return BadRequest(new
                    {
                        Message = "Certificate validation failed",
                        Errors = validationResult.Errors,
                        Warnings = validationResult.Warnings
                    });
                }

                // Decode document
                byte[] documentData;
                try
                {
                    documentData = Convert.FromBase64String(request.DocumentBase64);
                }
                catch
                {
                    return BadRequest(new { Message = "Invalid base64 encoded document" });
                }

                // Create detached signature
                var detachedSignature = _signatureService.CreateDetachedSignature(
                    documentData,
                    clientCert,
                    request.Algorithm
                );

                // Compute document hash
                byte[] documentHash;
                using (var hashAlgorithm = SHA256.Create())
                {
                    documentHash = hashAlgorithm.ComputeHash(documentData);
                }

                _logger.LogInformation("Document signed by {Subject} with thumbprint {Thumbprint}",
                    clientCert.Subject, clientCert.Thumbprint);

                var response = new SignResponse
                {
                    Success = true,
                    Signature = detachedSignature,
                    DocumentHash = BitConverter.ToString(documentHash).Replace("-", ""),
                    SignedBy = clientCert.Subject,
                    Timestamp = DateTime.UtcNow,
                    CertificateThumbprint = clientCert.Thumbprint,
                    Algorithm = request.Algorithm
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error signing document");
                return StatusCode(500, new
                {
                    Success = false,
                    Error = ex.Message,
                    Details = ex.InnerException?.Message
                });
            }
        }

        [HttpPost("verify")]
        [AllowAnonymous]
        public IActionResult VerifyDocument([FromBody] VerifyRequest request)
        {
            try
            {
                // Decode document
                byte[] documentData;
                try
                {
                    documentData = Convert.FromBase64String(request.DocumentBase64);
                }
                catch
                {
                    return BadRequest(new { Message = "Invalid base64 encoded document" });
                }

                // Verify detached signature
                var (isValid, signer, signingTime) = _signatureService.VerifyDetachedSignature(
                    documentData,
                    request.Signature
                );

                var response = new VerifyResponse
                {
                    IsValid = isValid,
                    Message = isValid ? "Signature is valid" : "Signature verification failed",
                    VerificationTime = DateTime.UtcNow,
                    VerifiedBy = signer,
                    Algorithm = "SHA256withRSA"
                };

                _logger.LogInformation("Document verification result: {IsValid} signed by {Signer}",
                    isValid, signer);

                return Ok(response);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying document");
                return BadRequest(new
                {
                    IsValid = false,
                    Message = "Error during verification",
                    Error = ex.Message
                });
            }
        }

        [HttpPost("sign-hash")]
        [Authorize(AuthenticationSchemes = "Certificate")]
        public IActionResult SignHash([FromBody] HashRequest request)
        {
            try
            {
                //var clientCert = HttpConnectionExtensions.GetClientCertificate(HttpContext);
                var clientCert = HttpContext.Connection.ClientCertificate;

                if (clientCert == null || !clientCert.HasPrivateKey)
                {
                    return Unauthorized("Valid client certificate with private key required");
                }

                // Decode hash
                byte[] hash;
                try
                {
                    hash = Convert.FromBase64String(request.HashBase64);
                }
                catch
                {
                    return BadRequest(new { Message = "Invalid base64 encoded hash" });
                }

                // Sign the hash
                var signature = _signatureService.SignHash(hash, clientCert, request.Algorithm);

                var response = new HashResponse
                {
                    Signature = Convert.ToBase64String(signature),
                    Algorithm = $"Hash-{request.Algorithm}-with-RSA",
                    CertificateThumbprint = clientCert.Thumbprint
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new
                {
                    Error = ex.Message
                });
            }
        }

        [HttpPost("verify-hash")]
        [AllowAnonymous]
        public IActionResult VerifyHash([FromBody] object request)
        {
            try
            {
                // This endpoint would require the hash, signature, and certificate
                // For simplicity, we'll just return a message
                return Ok(new
                {
                    Message = "Use the verify endpoint for document verification",
                    Note = "Hash verification requires original hash, signature, and public certificate"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Error = ex.Message });
            }
        }

        [HttpGet("create-test-document")]
        [AllowAnonymous]
        public IActionResult CreateTestDocument()
        {
            var testDocument = new
            {
                Title = "Test Document for Digital Signature",
                Content = "This is a sample document to demonstrate digital signatures.",
                CreatedAt = DateTime.UtcNow,
                Author = "Certificate Demo API",
                Version = "1.0"
            };

            var json = System.Text.Json.JsonSerializer.Serialize(testDocument);
            var bytes = Encoding.UTF8.GetBytes(json);
            var base64 = Convert.ToBase64String(bytes);

            return Ok(new
            {
                Message = "Test document created",
                DocumentBase64 = base64,
                Hash = BitConverter.ToString(SHA256.HashData(bytes)).Replace("-", ""),
                Size = bytes.Length
            });
        }
    }

}
