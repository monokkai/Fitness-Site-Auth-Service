namespace auth_service.Models.DTOs;

public class AuthResultDto
{
    public bool Success { get; set; }
    public string Token { get; set; }
    public UserDto User { get; set; }
    public string Error { get; set; }
} 