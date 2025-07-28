using System.Security.Claims;
using auth_service.Models.DTOs;
using auth_service.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace auth_service.Controllers;

[ApiController]
[Route("api/auth")]
[EnableCors]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IPasswordService _passwordService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, IPasswordService passwordService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _passwordService = passwordService;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
    {
        try
        {
            _logger.LogInformation("Registration attempt for email: {Email}", request.Email);

            if (string.IsNullOrEmpty(request.Username) || request.Username.Length < 3)
            {
                return BadRequest(new { success = false, message = "Username must be at least 3 characters" });
            }

            // Более строгая проверка email через regex
            var emailRegex = new System.Text.RegularExpressions.Regex(@"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$");
            if (string.IsNullOrEmpty(request.Email) || !emailRegex.IsMatch(request.Email))
            {
                return BadRequest(new { success = false, message = "Invalid email address" });
            }

            if (string.IsNullOrEmpty(request.Password) || request.Password.Length < 6)
            {
                return BadRequest(new { success = false, message = "Password must be at least 6 characters" });
            }

            var result = await _authService.RegisterAsync(request);

            if (result.User == null || result.Token == null)
            {
                return BadRequest(new { success = false, message = result.Error ?? "Registration failed" });
            }

            _logger.LogInformation("User registered successfully: {UserId}", result.User.Id);

            return Ok(new
            {
                success = true,
                token = result.Token,
                user = new
                {
                    id = result.User.Id,
                    username = result.User.Username,
                    email = result.User.Email
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration failed");
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        try
        {
            _logger.LogInformation("Login attempt for email: {Email}", request.Email);
            
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Email and password are required" });
            }

            var result = await _authService.LoginAsync(request);
            
            if (result == null)
            {
                _logger.LogWarning("Login failed for email: {Email}", request.Email);
                return Unauthorized(new { message = "Invalid email or password" });
            }

            _logger.LogInformation("Login successful for email: {Email}", request.Email);
            return Ok(new { token = result.Token, user = result.User });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for email: {Email}", request.Email);
            return StatusCode(500, new { message = "An error occurred during login" });
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            _logger.LogInformation("User logged out: {UserId}", userId);
            return Ok(new { success = true });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout failed");
            return BadRequest(new { success = false, message = "Logout failed" });
        }
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        try
        {
            if (!User.Identity.IsAuthenticated)
            {
                _logger.LogWarning("Unauthorized access attempt to /me endpoint");
                return Unauthorized(new { success = false, message = "Not authenticated" });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            _logger.LogInformation("Getting current user info for: {UserId}", userId);

            var user = await _authService.GetUserById(int.Parse(userId));

            return Ok(new
            {
                success = true,
                user = new
                {
                    id = user.Id,
                    username = user.Username,
                    email = user.Email
                }
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get current user");
            return BadRequest(new { success = false, message = ex.Message });
        }
    }
}