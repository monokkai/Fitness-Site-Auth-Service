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
            try
            {
                _logger.LogInformation($"Attempting to register user with email: {request.Email}");

                if (await _context.Users.AnyAsync(u => u.Email == request.Email))
                {
                    _logger.LogWarning($"Email already taken: {request.Email}");
                    throw new Exception("Email is already taken! Try another one!");
                }

                if (await _context.Users.AnyAsync(u => u.Username == request.Username))
                {
                    _logger.LogWarning($"Username already taken: {request.Username}");
                    throw new Exception("Username is already taken! Try another one!");
                }

                User user = new User
                {
                    Username = request.Username,
                    Email = request.Email,
                    PasswordHash = _passwordService.HashPassword(request.Password),
                    IsActive = true,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                _logger.LogInformation($"Creating new user: {user.Username}");
                _context.Users.Add(user);
                try
                {
                    await _context.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    throw new Exception("Error of it!", ex);
                }

                string token = _tokenService.GenerateToken(user);
                SetTokenCookie(token);
                _logger.LogInformation($"User created successfully: {user.Id}");

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to register user: {request.Email}");
                throw;
            }
        }

        public async Task<User> ValidateUser(string email, string password)
        {
            try
            {
                _logger.LogInformation($"Attempting to validate user with email: {email}");

                var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == email);
                if (user == null)
                {
                    _logger.LogWarning($"Login attempt with non-existent email: {email}");
                    throw new Exception("Invalid email or password");
                }

                _logger.LogInformation($"Found user with email {email}, hash in DB: {user.PasswordHash}");
                _logger.LogInformation($"Attempting to verify password for user {email}");

                bool isPasswordValid = _passwordService.VerifyPassword(password, user.PasswordHash);
                _logger.LogInformation($"Password verification result for {email}: {isPasswordValid}");

                if (!isPasswordValid)
                {
                    _logger.LogWarning($"Invalid password attempt for user: {email}");
                    throw new Exception("Invalid email or password");
                }

                user.LastLoginAt = DateTime.UtcNow;
                await _context.SaveChangesAsync();

                string token = _tokenService.GenerateToken(user);
                SetTokenCookie(token);
                _logger.LogInformation($"User logged in successfully: {user.Id}");

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login");
                throw;
            }
        }

        public async Task<User> GetUserById(int id)
        {
            try
            {
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Id == id);
                if (user == null)
                {
                    throw new Exception("User not found");
                }

                return user;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error getting user by id: {Id}", id);
                throw;
            }
        }

        public async Task<AuthResultDto> LoginAsync(LoginRequestDto request)
        {
            try
            {
                var user = await ValidateUserAsync(request.Email, request.Password);
                if (user == null)
                {
                    return new AuthResultDto
                    {
                        Token = null,
                        User = null,
                        Error = "Invalid email or password"
                    };
                }

                var token = _tokenService.GenerateToken(user);

                return new AuthResultDto
                {
                    Token = token,
                    User = new UserDto
                    {
                        Id = user.Id,
                        Username = user.Username,
                        Email = user.Email
                    },
                    Error = null
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for user {Email}", request.Email);
                return new AuthResultDto
                {
                    Token = null,
                    User = null,
                    Error = "An error occurred during login"
                };
            }
        }

        public async Task<AuthResultDto> RegisterAsync(RegisterRequestDto request)
        {
            try
            {
                if (!await IsEmailUniqueAsync(request.Email))
                {
                    return new AuthResultDto
                    {
                        Token = null,
                        User = null,
                        Error = "Email already exists"
                    };
                }

                if (!await IsUsernameUniqueAsync(request.Username))
                {
                    return new AuthResultDto
                    {
                        Token = null,
                        User = null,
                        Error = "Username already exists"
                    };
                }

                User user = await RegisterUser(request);
                string token = _tokenService.GenerateToken(user);

                return new AuthResultDto
                {
                    Token = token,
                    User = new UserDto
                    {
                        Id = user.Id,
                        Username = user.Username,
                        Email = user.Email
                    },
                    Error = null
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during registration for user {Email}", request.Email);
                return new AuthResultDto
                {
                    Token = null,
                    User = null,
                    Error = "An error occurred during registration"
                };
            }
        }

        public async Task<User?> ValidateUserAsync(string email, string password)
        {
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == email);

            if (user == null)
            {
                _logger.LogWarning($"Login attempt with non-existent email: {email}");
                return null;
            }

            _logger.LogInformation($"Found user with email {email}, verifying password...");

            bool isPasswordValid = _passwordService.VerifyPassword(password, user.PasswordHash);
            if (!isPasswordValid)
            {
                _logger.LogWarning($"Invalid password attempt for user: {email}");
                return null;
            }

            user.LastLoginAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            _logger.LogInformation($"User validated successfully: {user.Id}");

            return user;
        }

        public async Task<bool> IsEmailUniqueAsync(string email)
        {
            return !await _context.Users.AnyAsync(u => u.Email == email);
        }

        public async Task<bool> IsUsernameUniqueAsync(string username)
        {
            return !await _context.Users.AnyAsync(u => u.Username == username);
        }
    }
}