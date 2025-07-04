using auth_service.Models.DTOs;
using auth_service.Models.Entities;

namespace auth_service.Services.Interfaces
{
    public interface IAuthService
    {
        Task<User> RegisterUser(RegisterRequestDto request);
        Task<User> ValidateUser(string email, string password);
        Task<User> GetUserById(int id);
    }
}
