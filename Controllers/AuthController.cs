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
            if (string.IsNullOrEmpty(request.Username) || request.Username.Length < 3)
            {
                return BadRequest(new { success = false, message = "Username must be at least 3 characters" });
            }

            if (string.IsNullOrEmpty(request.Email) || !request.Email.Contains("@"))
            {
                return BadRequest(new { success = false, message = "Invalid email address" });
            }

            if (string.IsNullOrEmpty(request.Password) || request.Password.Length < 6)
            {
                return BadRequest(new { success = false, message = "Password must be at least 6 characters" });
            }

            var user = await _authService.RegisterUser(request);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme))
            );

            return Ok(new { 
                success = true, 
                user = new { 
                    id = user.Id, 
                    username = user.Username, 
                    email = user.Email 
                } 
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.Email) || !request.Email.Contains("@"))
            {
                return BadRequest(new { success = false, message = "Invalid email address" });
            }

            if (string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { success = false, message = "Password is required" });
            }

            var user = await _authService.ValidateUser(request.Email, request.Password);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme))
            );

            return Ok(new { 
                success = true, 
                user = new { 
                    id = user.Id, 
                    username = user.Username, 
                    email = user.Email 
                } 
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok(new { success = true });
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetCurrentUser()
    {
        if (!User.Identity.IsAuthenticated)
        {
            return Unauthorized(new { success = false, message = "Not authenticated" });
        }

        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _authService.GetUserById(int.Parse(userId));
            
            return Ok(new { 
                success = true, 
                user = new { 
                    id = user.Id, 
                    username = user.Username, 
                    email = user.Email 
                } 
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { success = false, message = ex.Message });
        }
    }
}