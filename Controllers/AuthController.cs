using System.Security.Claims;
using auth_service.Models.DTOs;
using auth_service.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace auth_service.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("signup")]
    public async Task<IActionResult> Signup([FromBody] RegisterRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var result = await _authService.Register(request);

        if (!result.Success)
        {
            return BadRequest(result);
        }

        return StatusCode(200);
    }

    [HttpPost("auth")]
    public async Task<IActionResult> Auth([FromBody] LoginRequestDto request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var result = await _authService.Login(request);

        if (!result.Success)
            return BadRequest(result);

        return Ok(result);
    }

    [Authorize]
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        string? userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        string? username = User.FindFirst(ClaimTypes.Name)?.Value;
        string? email = User.FindFirst(ClaimTypes.Email)?.Value;

        return Ok(new UserDto
        {
            Id = int.Parse(userId),
            Username = username,
            Email = email
        });
    }
}