using System.ComponentModel.DataAnnotations;

namespace auth_service.Models.Entities;

public class User
{
    public int Id { get; set; }
    [Required] [MaxLength(50)] public string Username { get; set; }
    [Required] [MaxLength(100)] public string Email { get; set; }
    [Required] public string PasswordHash { get; set; }
    public DateTime CreatedAt { get; set; }

    //Security
    public string RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiryTime { get; set; }
    public bool IsActive { get; set; }
    public DateTime? LastLoginAt { get; set; }
}