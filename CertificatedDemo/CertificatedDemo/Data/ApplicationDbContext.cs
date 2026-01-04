using CertificatedDemo.Models;

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CertificatedDemo.Data
{


    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Product> Products { get; set; }
        public DbSet<ApplicationUserClaim> ApplicationUserClaims { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure Product entity
            builder.Entity<Product>(entity =>
            {
                entity.HasIndex(p => p.Name);
                entity.HasIndex(p => p.Category);
                entity.HasIndex(p => p.CreatedAt);

                entity.Property(p => p.Price)
                    .HasPrecision(18, 2);

                entity.HasOne(p => p.CreatedByUser)
                    .WithMany()
                    .HasForeignKey(p => p.CreatedByUserId)
                    .OnDelete(DeleteBehavior.SetNull);
            });

            // Configure ApplicationUser
            builder.Entity<ApplicationUser>(entity =>
            {
                entity.HasIndex(u => u.Email).IsUnique();
                entity.HasMany(u => u.Claims)
                    .WithOne(c => c.User)
                    .HasForeignKey(c => c.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            // Seed initial data
            SeedData.Seed(builder);
            //// Seed initial data
            //ProductSeed.Seed(builder);
        }
    }
}
