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
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        ApplicationDbContext context,
        IPasswordService passwordService,
        ITokenService tokenService,
        ILogger<AuthService> logger)
    {
        _context = context;
        _passwordService = passwordService;
        _tokenService = tokenService;
        _logger = logger;
    }

    public async Task<AuthResultDto> Register(RegisterRequestDto request)
    {
        try
        {
            _logger.LogInformation($"Attempting to register user with email: {request.Email}");

            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            {
                _logger.LogWarning($"Email already taken: {request.Email}");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "Email is already taken! Try another one!"
                };
            }

            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                _logger.LogWarning($"Username already taken: {request.Username}");
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

            _logger.LogInformation($"Creating new user: {user.Username}");
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            string token = _tokenService.GenerateToken(user);
            _logger.LogInformation($"User created successfully: {user.Id}");

            return new AuthResultDto
            {
                Success = true,
                Token = token,
                User = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration");
            return new AuthResultDto
            {
                Success = false,
                Error = "An error occurred during registration. Please try again."
            };
        }
    }

    public async Task<AuthResultDto> Login(LoginRequestDto request)
    {
        try
        {
            User? user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);

            if (user == null)
            {
                _logger.LogWarning($"Login attempt with non-existent email: {request.Email}");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "Email is incorrect! Try a bit later!"
                };
            }

            if (!_passwordService.VerifyPassword(request.Password, user.PasswordHash))
            {
                _logger.LogWarning($"Invalid password attempt for user: {user.Email}");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "Password is incorrect! Try another one!"
                };
            }

            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            string token = _tokenService.GenerateToken(user);
            _logger.LogInformation($"User logged in successfully: {user.Id}");

            return new AuthResultDto
            {
                Success = true,
                Token = token,
                User = new UserDto
                {
                    Id = user.Id,
                    Username = user.Username,
                    Email = user.Email
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login");
            return new AuthResultDto
            {
                Success = false,
                Error = "An error occurred during login. Please try again."
            };
        }
    }
}