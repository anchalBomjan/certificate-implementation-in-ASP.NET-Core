using CertificatedDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Linq;

namespace CertificatedDemo.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class ProductController : ControllerBase
    {
        private static List<Product> _products = new List<Product>
        {
            new Product { Id = 1, Name = "Laptop", Description = "A high-performance laptop", Price = 1200, Quantity = 10, Category = "Electronics", IsActive = true },
            new Product { Id = 2, Name = "Mouse", Description = "A wireless mouse", Price = 25, Quantity = 50, Category = "Electronics", IsActive = true },
            new Product { Id = 3, Name = "Keyboard", Description = "A mechanical keyboard", Price = 80, Quantity = 30, Category = "Electronics", IsActive = true }
        };

        [HttpGet]
        [Authorize(Policy = "RequireProductsView")]
        public IActionResult GetProducts()
        {
            return Ok(_products.Where(p => p.IsActive));
        }

        [HttpGet("{id}")]
        [Authorize(Policy = "RequireProductsView")]
        public IActionResult GetProduct(int id)
        {
            var product = _products.FirstOrDefault(p => p.Id == id && p.IsActive);
            if (product == null)
            {
                return NotFound();
            }
            return Ok(product);
        }

        [HttpPost]
        [Authorize(Policy = "RequireProductsCreate")]
        public IActionResult CreateProduct([FromBody] ProductDto productDto)
        {
            if (productDto == null)
            {
                return BadRequest("Product data is null.");
            }

            var newProduct = new Product
            {
                Id = _products.Any() ? _products.Max(p => p.Id) + 1 : 1,
                Name = productDto.Name,
                Description = productDto.Description,
                Price = productDto.Price,
                Quantity = productDto.Quantity,
                Category = productDto.Category,
                IsActive = productDto.IsActive,
                CreatedAt = System.DateTime.UtcNow
            };

            _products.Add(newProduct);

            return CreatedAtAction(nameof(GetProduct), new { id = newProduct.Id }, newProduct);
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "RequireProductsEdit")]
        public IActionResult UpdateProduct(int id, [FromBody] ProductDto productDto)
        {
            if (productDto == null)
            {
                return BadRequest("Product data is invalid.");
            }

            var product = _products.FirstOrDefault(p => p.Id == id);
            if (product == null)
            {
                return NotFound();
            }

            product.Name = productDto.Name;
            product.Description = productDto.Description;
            product.Price = productDto.Price;
            product.Quantity = productDto.Quantity;
            product.Category = productDto.Category;
            product.IsActive = productDto.IsActive;
            product.UpdatedAt = System.DateTime.UtcNow;

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "RequireProductsDelete")]
        public IActionResult DeleteProduct(int id)
        {
            var product = _products.FirstOrDefault(p => p.Id == id);
            if (product == null)
            {
                return NotFound();
            }

            _products.Remove(product);

            return NoContent();
        }
    }
}
