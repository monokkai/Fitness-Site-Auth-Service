using auth_service.Models.DTOs;
using auth_service.Models.Entities;
using auth_service.Services.Interfaces;
using Microsoft.EntityFrameworkCore;

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

    public async Task<AuthResultDto> Register(RegisterRequestDto request)
    {
        if (await _context.Users.AnyAsync((user) => user.Email == request.Email))
        {
            return new AuthResultDto
            {
                Success = false,
                Error = "Email is already taken! Try another one!"
            };
        }

        if (await _context.Users.AnyAsync((user) => user.Username == request.Username))
        {
            return new AuthResultDto
            {
                Success = false,
                Error = "Username is already taken! Try another one!"
            };
        }

        User user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = _passwordService.HashPassword(request.Password),
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        string token = _tokenService.GenerateToken(user);

        return new AuthResultDto
        {
            Success = true,
            Token = token,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
            }
        };
    }

    public async Task<AuthResultDto> Login(LoginRequestDto request)
    {
        User? user = await _context.Users.FirstOrDefaultAsync((user) => user.Email == request.Email);

        if (user == null)
        {
            return new AuthResultDto
            {
                Success = false,
                Error = "Email is incorrect! Try a bit later!"
            };
        }

        if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
        {
            return new AuthResultDto
            {
                Success = false,
                Error = "Password is incorrect! Try another one!"
            };
        }

        user.LastLoginAt = DateTime.UtcNow;
        string token = _tokenService.GenerateToken(user);

        return new AuthResultDto
        {
            Success = true,
            Token = token,
            User = new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
            }
        };
    }
}