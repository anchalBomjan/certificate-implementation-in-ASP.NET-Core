namespace CertificatedDemo.Models
{
    public class UserResponse
    {
        public string Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string FullName => $"{FirstName} {LastName}";
        public string? PhoneNumber { get; set; }
        public List<string> Roles { get; set; } = new();
        public List<ClaimResponse> Claims { get; set; } = new();
        public DateTime CreatedAt { get; set; }
    }
}
