using CertificatedDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace CertificatedDemo.Services
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public TokenService(
            IConfiguration configuration,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _configuration = configuration;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<AuthResponse> GenerateTokenAsync(ApplicationUser user)
        {
            var claims = await GetClaimsAsync(user);
            var token = GenerateJwtToken(claims);

            var userResponse = new UserResponse
            {
                Id = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName!,
                LastName = user.LastName!,
                PhoneNumber = user.PhoneNumber,
                CreatedAt = user.CreatedAt
            };

            // Get user roles
            userResponse.Roles = (await _userManager.GetRolesAsync(user)).ToList();

            // Get user claims
            var userClaims = await _userManager.GetClaimsAsync(user);
            userResponse.Claims = userClaims.Select(c => new ClaimResponse
            {
                Type = c.Type,
                Value = c.Value
            }).ToList();

            // Get permissions from roles and user claims
            var permissions = await GetUserPermissionsAsync(user);

            return new AuthResponse
            {
                Token = token,
                Expiration = DateTime.UtcNow.AddMinutes(
                    double.Parse(_configuration["Jwt:ExpireMinutes"] ?? "60")),
                User = userResponse,
                Permissions = permissions
            };
        }

        private async Task<List<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName!),
            new(ClaimTypes.Email, user.Email!),
            new("firstName", user.FirstName ?? ""),
            new("lastName", user.LastName ?? ""),
            new("fullName", $"{user.FirstName} {user.LastName}")
        };

            // Add roles
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
                claims.Add(new Claim("role", role));
            }

            // Add user-specific claims
            var userClaims = await _userManager.GetClaimsAsync(user);
            claims.AddRange(userClaims);

            // Add permissions from roles
            var permissions = await GetUserPermissionsAsync(user);
            foreach (var permission in permissions)
            {
                claims.Add(new Claim("Permission", permission));
            }

            return claims;
        }

        private string GenerateJwtToken(List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not configured")));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    double.Parse(_configuration["Jwt:ExpireMinutes"] ?? "60")),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public ClaimsPrincipal ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _configuration["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _configuration["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch
            {
                throw new SecurityTokenException("Invalid token");
            }
        }

        private async Task<List<string>> GetUserPermissionsAsync(ApplicationUser user)
        {
            var permissions = new List<string>();

            // Get permissions from roles
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var roleName in userRoles)
            {
                var role = await _roleManager.FindByNameAsync(roleName);
                if (role != null)
                {
                    var roleClaims = await _roleManager.GetClaimsAsync(role);
                    permissions.AddRange(roleClaims
                        .Where(c => c.Type == "Permission")
                        .Select(c => c.Value));
                }
            }

            // Get permissions from user claims
            var userClaims = await _userManager.GetClaimsAsync(user);
            permissions.AddRange(userClaims
                .Where(c => c.Type == "Permission")
                .Select(c => c.Value));

            return permissions.Distinct().ToList();
        }
    }
}