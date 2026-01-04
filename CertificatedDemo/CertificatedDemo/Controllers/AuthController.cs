using CertificatedDemo.Models;
using CertificatedDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CertificatedDemo.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ITokenService _tokenService;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ITokenService tokenService,
            RoleManager<IdentityRole> roleManager,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _tokenService = tokenService;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber,
                CreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Assign default role
                await _userManager.AddToRoleAsync(user, Roles.User);

                // Add default claims
                await _userManager.AddClaimAsync(user,
                    new System.Security.Claims.Claim("registration_date", DateTime.UtcNow.ToString("o")));

                _logger.LogInformation("User {Email} registered successfully", model.Email);

                var tokenResponse = await _tokenService.GenerateTokenAsync(user);
                return Ok(tokenResponse);
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized(new { message = "Invalid email or password" });

            // Check if user is active
            if (!user.EmailConfirmed)
                return Unauthorized(new { message = "Please confirm your email" });

            var tokenResponse = await _tokenService.GenerateTokenAsync(user);

            _logger.LogInformation("User {Email} logged in successfully", model.Email);

            return Ok(tokenResponse);
        }

        [HttpPost("change-password")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            var result = await _userManager.ChangePasswordAsync(
                user, model.CurrentPassword, model.NewPassword);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} changed password successfully", user.Email);
                return Ok(new { message = "Password changed successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("profile")]
        [Authorize]
        public async Task<IActionResult> GetProfile()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            var roles = await _userManager.GetRolesAsync(user);
            var claims = await _userManager.GetClaimsAsync(user);

            var response = new UserResponse
            {
                Id = user.Id,
                Email = user.Email!,
                FirstName = user.FirstName!,
                LastName = user.LastName!,
                PhoneNumber = user.PhoneNumber,
                Roles = roles.ToList(),
                Claims = claims.Select(c => new ClaimResponse
                {
                    Type = c.Type,
                    Value = c.Value
                }).ToList(),
                CreatedAt = user.CreatedAt
            };

            return Ok(response);
        }

        [HttpPut("profile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.PhoneNumber = model.PhoneNumber;
            user.UpdatedAt = DateTime.UtcNow;

            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
                return Ok(new { message = "Profile updated successfully" });

            return BadRequest(result.Errors);
        }

        [HttpGet("permissions")]
        [Authorize]
        public async Task<IActionResult> GetPermissions()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Unauthorized();

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

            return Ok(permissions.Distinct());
        }

        [HttpGet("roles")]
        [Authorize(Roles = Roles.Admin)]
        public IActionResult GetRoles()
        {
            return Ok(Roles.GetAllRoles());
        }

        [HttpGet("all-permissions")]
        [Authorize(Roles = Roles.Admin)]
        public IActionResult GetAllPermissions()
        {
            return Ok(Permissions.GetAllPermissions());
        }
    }

    public class UpdateProfileModel
    {
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string? PhoneNumber { get; set; }
    }

}
