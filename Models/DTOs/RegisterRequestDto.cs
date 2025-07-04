using System.ComponentModel.DataAnnotations;

namespace auth_service.Models.DTOs;

public class RegisterRequestDto
{
    public string Username { get; set; }

    public string Email { get; set; }

    public string Password { get; set; }
}