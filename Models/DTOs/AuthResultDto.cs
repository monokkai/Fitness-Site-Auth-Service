namespace auth_service.Models.DTOs;

public class AuthResultDto
{
    // Checking for CI/CD Pipeline
    // Check 2
    public bool Success { get; set; }
    public string? Token { get; set; }
    public UserDto? User { get; set; }
    public string? Error { get; set; }
}
