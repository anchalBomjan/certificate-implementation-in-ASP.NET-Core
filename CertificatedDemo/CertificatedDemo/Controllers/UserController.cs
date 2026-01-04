using CertificatedDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace CertificatedDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = Roles.Admin)]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<UsersController> _logger;

        public UsersController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<UsersController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> GetUsers(
            [FromQuery] string? search,
            [FromQuery] int page = 1,
            [FromQuery] int pageSize = 20)
        {
            var query = _userManager.Users.AsQueryable();

            if (!string.IsNullOrEmpty(search))
            {
                query = query.Where(u =>
                    u.Email!.Contains(search) ||
                    u.FirstName!.Contains(search) ||
                    u.LastName!.Contains(search) ||
                    u.PhoneNumber!.Contains(search));
            }

            var totalCount = await query.CountAsync();
            var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

            var users = await query
                .OrderByDescending(u => u.CreatedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            var userResponses = new List<UserResponse>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var claims = await _userManager.GetClaimsAsync(user);

                userResponses.Add(new UserResponse
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
                });
            }

            var result = new PagedResponse<UserResponse>
            {
                Items = userResponses,
                Page = page,
                PageSize = pageSize,
                TotalCount = totalCount,
                TotalPages = totalPages
            };

            return Ok(result);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

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

        [HttpPost("{id}/roles")]
        public async Task<IActionResult> AssignRole(string id, [FromBody] AssignRoleModel model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            // Check if role exists
            if (!await _roleManager.RoleExistsAsync(model.RoleName))
                return BadRequest(new { message = $"Role '{model.RoleName}' does not exist" });

            var result = await _userManager.AddToRoleAsync(user, model.RoleName);

            if (result.Succeeded)
            {
                _logger.LogInformation("Role {Role} assigned to user {Email}",
                    model.RoleName, user.Email);
                return Ok(new { message = $"Role '{model.RoleName}' assigned successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpDelete("{id}/roles/{roleName}")]
        public async Task<IActionResult> RemoveRole(string id, string roleName)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            if (!await _userManager.IsInRoleAsync(user, roleName))
                return BadRequest(new { message = $"User is not in role '{roleName}'" });

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);

            if (result.Succeeded)
            {
                _logger.LogInformation("Role {Role} removed from user {Email}",
                    roleName, user.Email);
                return Ok(new { message = $"Role '{roleName}' removed successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("{id}/claims")]
        public async Task<IActionResult> AddClaim(string id, [FromBody] AddClaimModel model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var claim = new System.Security.Claims.Claim(model.ClaimType, model.ClaimValue);
            var result = await _userManager.AddClaimAsync(user, claim);

            if (result.Succeeded)
            {
                _logger.LogInformation("Claim {ClaimType}={ClaimValue} added to user {Email}",
                    model.ClaimType, model.ClaimValue, user.Email);
                return Ok(new { message = "Claim added successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpGet("{id}/permissions")]
        public async Task<IActionResult> GetUserPermissions(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

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

        [HttpPost("lock/{id}")]
        public async Task<IActionResult> LockUser(string id, [FromBody] LockUserModel model)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var result = await _userManager.SetLockoutEndDateAsync(user,
                DateTimeOffset.UtcNow.Add(model.Duration));

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} locked for {Duration}",
                    user.Email, model.Duration);
                return Ok(new { message = $"User locked for {model.Duration}" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("unlock/{id}")]
        public async Task<IActionResult> UnlockUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
                return NotFound(new { message = "User not found" });

            var result = await _userManager.SetLockoutEndDateAsync(user, null);

            if (result.Succeeded)
            {
                _logger.LogInformation("User {Email} unlocked", user.Email);
                return Ok(new { message = "User unlocked successfully" });
            }

            return BadRequest(result.Errors);
        }
    }

    public class AssignRoleModel
    {
        [Required]
        public string RoleName { get; set; } = string.Empty;
    }

    public class AddClaimModel
    {
        [Required]
        public string ClaimType { get; set; } = string.Empty;

        [Required]
        public string ClaimValue { get; set; } = string.Empty;
    }

    public class LockUserModel
    {
        [Required]
        public TimeSpan Duration { get; set; } = TimeSpan.FromHours(1);
    }
}
