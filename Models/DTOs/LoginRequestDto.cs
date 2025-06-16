using System.ComponentModel.DataAnnotations;

namespace auth_service.Models.DTOs;

public class LoginRequestDto
{
    [Required] [EmailAddress] public string Email { get; set; }
    [Required] [MinLength(6)] public string Password { get; set; }
}