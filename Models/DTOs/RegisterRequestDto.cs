using System.ComponentModel.DataAnnotations;

namespace auth_service.Models.DTOs;

public class RegisterRequestDto
{
    [Required] [MinLength(3)] public string Username { get; set; }

    [Required] [EmailAddress] public string Email { get; set; }

    [Required] [MinLength(6)] public string Password { get; set; }
}