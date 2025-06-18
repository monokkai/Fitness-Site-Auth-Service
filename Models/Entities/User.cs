using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace auth_service.Models.Entities;

[Table("Users")]
public class User
{
    [Column("UserId")]
    public int Id { get; set; }

    [Required]
    [MaxLength(50)]
    public string Username { get; set; }

    [Required]
    [MaxLength(100)]
    public string Email { get; set; }

    [Required]
    public string PasswordHash { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public bool IsActive { get; set; }

    // Security - not mapped to database
    [NotMapped]
    public string RefreshToken { get; set; }

    [NotMapped]
    public DateTime? RefreshTokenExpiryTime { get; set; }
}