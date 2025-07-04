using auth_service.Models.DTOs;
using auth_service.Models.Entities;
using auth_service.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace auth_service.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly IPasswordService _passwordService;
        private readonly ITokenService _tokenService;
        private readonly ILogger<AuthService> _logger;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthService(
            ApplicationDbContext context,
            IPasswordService passwordService,
            ITokenService tokenService,
            ILogger<AuthService> logger,
            IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _passwordService = passwordService;
            _tokenService = tokenService;
            _logger = logger;
            _httpContextAccessor = httpContextAccessor;
        }

        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                Expires = DateTimeOffset.UtcNow.AddDays(7),
                Path = "/"
            };

            _httpContextAccessor.HttpContext?.Response.Cookies.Append("auth_token", token, cookieOptions);
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
                SetTokenCookie(token);
                _logger.LogInformation($"User created successfully: {user.Id}");

                return new AuthResultDto
                {
                    Success = true,
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
                SetTokenCookie(token);
                _logger.LogInformation($"User logged in successfully: {user.Id}");

                return new AuthResultDto
                {
                    Success = true,
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

        public async Task<AuthResultDto> GetCurrentUser()
        {
            try
            {
                var userId = _httpContextAccessor.HttpContext?.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrEmpty(userId))
                {
                    return new AuthResultDto
                    {
                        Success = false,
                        Error = "No authenticated user found"
                    };
                }

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == int.Parse(userId));

                if (user == null)
                {
                    return new AuthResultDto
                    {
                        Success = false,
                        Error = "User not found"
                    };
                }

                return new AuthResultDto
                {
                    Success = true,
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
                _logger.LogError(ex, "Error getting current user");
                return new AuthResultDto
                {
                    Success = false,
                    Error = "An error occurred while getting current user"
                };
            }
        }

        public async Task<User> RegisterUser(RegisterRequestDto request)
        {
            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            {
                throw new Exception("User with this email already exists");
            }

            var hashedPassword = _passwordService.HashPassword(request.Password);
            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = hashedPassword
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return user;
        }

        public async Task<User> ValidateUser(string email, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                throw new Exception("Invalid email or password");
            }

            if (!_passwordService.VerifyPassword(password, user.PasswordHash))
            {
                throw new Exception("Invalid email or password");
            }

            return user;
        }

        public async Task<User> GetUserById(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                throw new Exception("User not found");
            }
            return user;
        }
    }
}