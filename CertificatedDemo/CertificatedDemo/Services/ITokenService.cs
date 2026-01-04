using CertificatedDemo.Models;
using System.Security.Claims;

namespace CertificatedDemo.Services
{
    public interface ITokenService
    {

        Task<AuthResponse> GenerateTokenAsync(ApplicationUser user);
        ClaimsPrincipal ValidateToken(string token);
    }
}
