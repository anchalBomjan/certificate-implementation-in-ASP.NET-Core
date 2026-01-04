using CertificatedDemo.Models;
using Microsoft.EntityFrameworkCore;

namespace CertificatedDemo.Data
{


    public static class ProductSeed
    {
        public static void Seed(ModelBuilder builder)
        {
            builder.Entity<Product>().HasData(
                new Product
                {
                    Id = 1,
                    Name = "Laptop",
                    Category = "Electronics",
                    Price = 1299.99m,
                    Quantity = 50,
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow
                }
            );
        }
    }

}

