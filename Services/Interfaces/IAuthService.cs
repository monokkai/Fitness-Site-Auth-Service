namespace auth_service.Services.Interfaces;
using auth_service.Models.DTOs;

public interface IAuthService
{
    Task<AuthResultDto> Register(RegisterRequestDto request);
    Task<AuthResultDto> Login(LoginRequestDto request);
}
