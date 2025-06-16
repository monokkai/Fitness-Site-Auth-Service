using auth_service.Models.DTOs;
using auth_service.Services.Interfaces;

namespace auth_service.Services;

public class AuthService : IAuthService
{
    private readonly ApplicationDbContext _context;
    private readonly IPasswordService _passwordService;
    private readonly ITokenService _tokenService;

    public AuthService(
        ApplicationDbContext context,
        IPasswordService passwordService,
        ITokenService tokenService)
    {
        _context = context;
        _passwordService = passwordService;
        _tokenService = tokenService;
    }

    public Task<AuthResultDto> Register(RegisterRequestDto request)
    {
        
    }

    public Task<AuthResultDto> Login(LoginRequestDto request)
    {
        throw new NotImplementedException();
    }
}