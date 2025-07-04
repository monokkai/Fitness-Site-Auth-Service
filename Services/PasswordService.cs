using auth_service.Services.Interfaces;
using BCrypt.Net;
using Microsoft.Extensions.Logging;

namespace auth_service.Services;

public class PasswordService : IPasswordService
{
    private const int WORK_FACTOR = 11;
    private readonly ILogger<PasswordService> _logger;

    public PasswordService(ILogger<PasswordService> logger)
    {
        _logger = logger;
    }

    public string HashPassword(string password)
    {
        var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: WORK_FACTOR);
        _logger.LogInformation($"Generated hash with work factor {WORK_FACTOR}: {hash}");
        return hash;
    }

    public bool VerifyPassword(string password, string hash)
    {
        try
        {
            var isValid = BCrypt.Net.BCrypt.Verify(password, hash);
            _logger.LogInformation($"Password verification result: {isValid}, hash: {hash}");
            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Error verifying password against hash: {hash}");
            return false;
        }
    }
}