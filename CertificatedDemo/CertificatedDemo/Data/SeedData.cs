using CertificatedDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace CertificatedDemo.Data
{
 


    public static class SeedData
    {
        public static void Seed(ModelBuilder builder)
        {
            // Seed Roles
            var roles = Roles.GetAllRoles();
            var roleIds = new Dictionary<string, string>();

            foreach (var role in roles)
            {
                var roleId = Guid.NewGuid().ToString();
                roleIds[role] = roleId;

                builder.Entity<IdentityRole>().HasData(
                    new IdentityRole
                    {
                        Id = roleId,
                        Name = role,
                        NormalizedName = role.ToUpper(),
                        ConcurrencyStamp = Guid.NewGuid().ToString()
                    }
                );
            }

            // Seed Admin User
            var adminUserId = Guid.NewGuid().ToString();
            var hasher = new PasswordHasher<ApplicationUser>();

            var adminUser = new ApplicationUser
            {
                Id = adminUserId,
                UserName = "admin@certificatesdemo.com",
                NormalizedUserName = "ADMIN@CERTIFICATESDEMO.COM",
                Email = "admin@certificatesdemo.com",
                NormalizedEmail = "ADMIN@CERTIFICATESDEMO.COM",
                EmailConfirmed = true,
                FirstName = "Admin",
                LastName = "User",
                PhoneNumber = "1234567890",
                PhoneNumberConfirmed = true,
                SecurityStamp = Guid.NewGuid().ToString(),
                ConcurrencyStamp = Guid.NewGuid().ToString(),
                CreatedAt = DateTime.UtcNow
            };

            adminUser.PasswordHash = hasher.HashPassword(adminUser, "Admin@123");

            builder.Entity<ApplicationUser>().HasData(adminUser);

            // Assign Admin role to admin user
            builder.Entity<IdentityUserRole<string>>().HasData(
                new IdentityUserRole<string>
                {
                    UserId = adminUserId,
                    RoleId = roleIds[Roles.Admin]
                }
            );

            // Seed Products
            var products = new List<Product>
        {
            new Product
            {
                Id = 1,
                Name = "Laptop",
                Description = "High-performance laptop with 16GB RAM and 512GB SSD",
                Price = 1299.99m,
                Quantity = 50,
                Category = "Electronics",
             
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                CreatedByUserId = adminUserId
            },
            new Product
            {
                Id = 2,
                Name = "Smartphone",
                Description = "Latest smartphone with 128GB storage and dual camera",
                Price = 799.99m,
                Quantity = 100,
                Category = "Electronics",
             
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                CreatedByUserId = adminUserId
            },
            new Product
            {
                Id = 3,
                Name = "Headphones",
                Description = "Wireless noise-cancelling headphones",
                Price = 299.99m,
                Quantity = 200,
                Category = "Audio",
              
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                CreatedByUserId = adminUserId
            }
        };

            builder.Entity<Product>().HasData(products);
        }

        public static async Task InitializeAsync(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            // Create roles if they don't exist
            foreach (var role in Roles.GetAllRoles())
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    await roleManager.CreateAsync(new IdentityRole(role));
                }
            }

            // Assign permissions to roles
            foreach (var rolePermission in Permissions.RolePermissions)
            {
                var role = await roleManager.FindByNameAsync(rolePermission.Key);
                if (role != null)
                {
                    // Clear existing claims
                    var existingClaims = await roleManager.GetClaimsAsync(role);
                    foreach (var claim in existingClaims)
                    {
                        await roleManager.RemoveClaimAsync(role, claim);
                    }

                    // Add new claims
                    foreach (var permission in rolePermission.Value)
                    {
                        await roleManager.AddClaimAsync(role,
                            new Claim("Permission", permission));
                    }
                }
            }

            // Create admin user if doesn't exist
            var adminEmail = "admin@certificatesdemo.com";
            var adminUser = await userManager.FindByEmailAsync(adminEmail);
            if (adminUser == null)
            {
                adminUser = new ApplicationUser
                {
                    UserName = adminEmail,
                    Email = adminEmail,
                    FirstName = "Admin",
                    LastName = "User",
                    PhoneNumber = "1234567890",
                    EmailConfirmed = true,
                    CreatedAt = DateTime.UtcNow
                };

                var result = await userManager.CreateAsync(adminUser, "Admin@123");
                if (result.Succeeded)
                {
                    await userManager.AddToRoleAsync(adminUser, Roles.Admin);

                    // Add custom claims to admin
                    await userManager.AddClaimAsync(adminUser,
                        new Claim("Permission", Permissions.CertificatesManage));
                    await userManager.AddClaimAsync(adminUser,
                        new Claim("CertificateAccess", "Full"));
                }
            }

            // Create sample users
            var sampleUsers = new[]
            {
            new { Email = "manager@certificatesdemo.com", Role = Roles.Manager, Password = "Manager@123" },
            new { Email = "user@certificatesdemo.com", Role = Roles.User, Password = "User@123" }
        };

            foreach (var sample in sampleUsers)
            {
                var user = await userManager.FindByEmailAsync(sample.Email);
                if (user == null)
                {
                    user = new ApplicationUser
                    {
                        UserName = sample.Email,
                        Email = sample.Email,
                        FirstName = sample.Role,
                        LastName = "User",
                        EmailConfirmed = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    var result = await userManager.CreateAsync(user, sample.Password);
                    if (result.Succeeded)
                    {
                        await userManager.AddToRoleAsync(user, sample.Role);
                    }
                }
            }
        }
    }
}
