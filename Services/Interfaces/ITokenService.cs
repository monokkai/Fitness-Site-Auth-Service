namespace auth_service.Services.Interfaces;
using auth_service.Models.Entities;

public interface ITokenService
{
    string GenerateToken(User user);
    bool ValidateToken(string token);
}