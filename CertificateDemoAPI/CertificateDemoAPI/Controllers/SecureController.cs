using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CertificateDemoAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = "Certificate")]
    public class SecureController : ControllerBase
    {
        [HttpGet("protected-data")]
        public IActionResult GetProtectedData()
        {
            var user = User.Identity;
            var certificate = HttpContext.Connection.ClientCertificate;

            var data = new
            {
                Message = "This is protected data accessible only with valid client certificate",
                AuthenticatedUser = user?.Name,
                AuthenticationType = user?.AuthenticationType,
                CertificateSubject = certificate?.Subject,
                CertificateThumbprint = certificate?.Thumbprint,
                AccessTime = DateTime.UtcNow,
                Claims = User.Claims.Select(c => new { c.Type, c.Value })
            };

            return Ok(data);
        }

        [HttpGet("admin-data")]
        [Authorize(Policy = "RequireClientCertificate")]
        public IActionResult GetAdminData()
        {
            var certificate = HttpContext.Connection.ClientCertificate;

            // Additional authorization logic based on certificate
            var isAdmin = certificate?.Subject?.Contains("CN=Admin") == true;

            if (!isAdmin)
            {
                return Forbid("Admin certificate required");
            }

            return Ok(new
            {
                Message = "Admin data accessed successfully",
                IsAdmin = true,
                CertificateInfo = new
                {
                    certificate.Subject,
                    certificate.Thumbprint,
                    certificate.Issuer
                },
                Time = DateTime.UtcNow
            });
        }

        [HttpPost("echo")]
        public IActionResult Echo([FromBody] object data)
        {
            var certificate = HttpContext.Connection.ClientCertificate;

            return Ok(new
            {
                OriginalData = data,
                SignedBy = certificate?.Subject,
                ReceivedAt = DateTime.UtcNow,
                IsSecure = Request.IsHttps
            });
        }
    }


}
