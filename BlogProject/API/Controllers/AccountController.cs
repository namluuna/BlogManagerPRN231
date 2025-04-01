using API.Data;
using API.Infrastructure;
using API.Models;
using CLIENT.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace API.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly BlogManagementContext _context;
    private readonly ILogger<AccountController> _logger;
    private readonly IJwtAuthManager _jwtAuthManager;
    private readonly IConfiguration _configuration;

    public AccountController(ILogger<AccountController> logger, IJwtAuthManager jwtAuthManager, IConfiguration configuration, BlogManagementContext context)
    {
        _logger = logger;
        _jwtAuthManager = jwtAuthManager;
        _configuration = configuration;
        _context = context;
    }

    [HttpGet("TestHashing")]
    [AllowAnonymous]
    public ActionResult TestHashing(string request)
    {
        return Ok(PasswordHasher.HashPassword(request));
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest("Invalid request.");

        var user = _context.Users.FirstOrDefault(x => x.Email == request.UserName);
        if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
            return Unauthorized("Invalid username or password.");

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Email),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var jwtResult = _jwtAuthManager.GenerateTokens(request.UserName, claims, DateTime.Now);
        _logger.LogInformation($"User [{request.UserName}] logged in the system.");

        return Ok(new LoginResult
        {
            UserName = user.Email,
            Role = user.Role,
            AccessToken = jwtResult.AccessToken,
            RefreshToken = jwtResult.RefreshToken.TokenString
        });
    }

    [HttpGet("user")]
    public ActionResult GetCurrentUser()
    {
        return Ok(new LoginResult
        {
            UserName = User.Identity?.Name!,
            Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty,
            OriginalUserName = User.FindFirst("OriginalUserName")?.Value ?? string.Empty
        });
    }

    [HttpPost("logout")]
    public ActionResult Logout()
    {
        var userName = User.Identity?.Name!;
        _jwtAuthManager.RemoveRefreshTokenByUserName(userName);
        _logger.LogInformation($"User [{userName}] logged out the system.");
        return Ok("Logged out successfully.");
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public ActionResult Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest("Invalid request.");

        if (_context.Users.Any(x => x.Email == request.Email))
            return Conflict("Email already exists.");

        var newUser = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = PasswordHasher.HashPassword(request.Password),
            Role = "Author",
            CreatedAt = DateTime.UtcNow
        };

        _context.Users.Add(newUser);
        _context.SaveChanges();
        return Ok("Account registered successfully.");
    }

    [HttpPost("change-password")]
    public ActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest("Invalid request.");

        var user = _context.Users.FirstOrDefault(x => x.Email == User.Identity.Name);
        if (user == null)
            return NotFound("User not found.");

        if (!PasswordHasher.VerifyPassword(request.OldPassword, user.PasswordHash))
            return BadRequest("Old password is incorrect.");

        user.PasswordHash = PasswordHasher.HashPassword(request.NewPassword);
        _context.SaveChanges();
        return Ok("Password changed successfully.");
    }
}

public class ChangePasswordRequest
{
    [Required]
    [JsonPropertyName("oldPassword")]
    public string OldPassword { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    [JsonPropertyName("newPassword")]
    public string NewPassword { get; set; } = string.Empty;
}

public class LoginRequest
{
    [Required]
    [JsonPropertyName("username")]
    public string UserName { get; set; } = string.Empty;

    [Required]
    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;
}

public class RegisterRequest
{
    [Required]
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;
}

public class LoginResult
{
    [JsonPropertyName("username")]
    public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("role")]
    public string Role { get; set; } = string.Empty;

    [JsonPropertyName("originalUserName")]
    public string OriginalUserName { get; set; } = string.Empty;

    [JsonPropertyName("accessToken")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refreshToken")]
    public string RefreshToken { get; set; } = string.Empty;
}
