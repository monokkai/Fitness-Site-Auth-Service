using auth_service.Models.DTOs;
using auth_service.Models.Entities;

namespace auth_service.Services.Interfaces
{
    public interface IAuthService
    {
        Task<AuthResultDto> LoginAsync(LoginRequestDto request);
        Task<AuthResultDto> RegisterAsync(RegisterRequestDto request);
        Task<User?> ValidateUserAsync(string email, string password);
        Task<bool> IsEmailUniqueAsync(string email);
        Task<bool> IsUsernameUniqueAsync(string username);
        Task<User> RegisterUser(RegisterRequestDto request);
        Task<User> GetUserById(int id);
    }
}
