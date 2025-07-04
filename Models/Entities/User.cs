using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace auth_service.Models.Entities;

[Table("Users")]
public class User
{
    [Key]
    [Column("Id")]
    public long Id { get; set; }
    
    [Required]
    [StringLength(50)]
    public string Username { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    [StringLength(255)]
    public string PasswordHash { get; set; } = string.Empty;
    
    [Column(TypeName = "timestamp")]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public DateTime CreatedAt { get; set; }
    
    [Column(TypeName = "timestamp")]
    [DatabaseGenerated(DatabaseGeneratedOption.Computed)]
    public DateTime UpdatedAt { get; set; }
    
    [Column(TypeName = "timestamp")]
    public DateTime? LastLoginAt { get; set; }
    
    public bool IsActive { get; set; } = true;

    [StringLength(255)]
    public string? RefreshToken { get; set; }

    public DateTime? RefreshTokenExpiryTime { get; set; }
}