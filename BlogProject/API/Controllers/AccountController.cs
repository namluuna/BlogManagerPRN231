using API.Data;
using API.Infrastructure;
using API.Models;
using CLIENT.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Json.Serialization;

namespace API.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]

public class AccountController: ControllerBase
{
    Data.BlogManagementContext context;
    ILogger<AccountController> logger;
    IJwtAuthManager jwtAuthManager;
    IConfiguration configuration;
    public AccountController(ILogger<AccountController> logger, IJwtAuthManager jwtAuthManager, IConfiguration configuration, Data.BlogManagementContext context)
    {
        this.logger = logger;
        this.jwtAuthManager = jwtAuthManager;
        this.configuration = configuration;
        this.context = context;
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest();
        }
        var confirm = context.Users.FirstOrDefault(u => u.Username == request.UserName);
        if (confirm != null) { 
            if(!PasswordHasher.VerifyPassword(request.Password, confirm.PasswordHash))
            {
                return Unauthorized();
            }
        }
        //if (context.Users.FirstOrDefault(x => x.Email == request.UserName && PasswordHasher.VerifyPassword(request.Password,x.PasswordHash)) == null)
        //{
        //    return Unauthorized();
        //}

        var role = GetRole(request.UserName);
        var claims = new[]
        {
            new Claim(ClaimTypes.Name,request.UserName),
            new Claim(ClaimTypes.Role, role)
        };

        var jwtResult = jwtAuthManager.GenerateTokens(request.UserName, claims, DateTime.Now);
        logger.LogInformation($"User [{request.UserName}] logged in the system.");
        return Ok(new
        {
            UserName = request.UserName,
            Role = role,
            AccessToken = jwtResult.AccessToken,
            RefreshToken = jwtResult.RefreshToken.TokenString
        });
    }

    [HttpGet("user")]
    [Authorize]
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
    [Authorize]
    public ActionResult Logout()
    {

        var userName = User.Identity?.Name!;
        jwtAuthManager.RemoveRefreshTokenByUserName(userName);
        logger.LogInformation("User [{userName}] logged out the system.", userName);
        return Ok();
    }

    [HttpPost("refresh-token")]
    [Authorize]
    public async Task<ActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var userName = User.Identity?.Name!;
            logger.LogInformation("User [{userName}] is trying to refresh JWT token.", userName);

            if (string.IsNullOrWhiteSpace(request.RefreshToken))
            {
                return Unauthorized();
            }

            var accessToken = await HttpContext.GetTokenAsync("Bearer", "access_token");
            var jwtResult = jwtAuthManager.Refresh(request.RefreshToken, accessToken ?? string.Empty, DateTime.Now);
            logger.LogInformation("User [{userName}] has refreshed JWT token.", userName);
            return Ok(new LoginResult
            {
                UserName = userName,
                Role = User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty,
                AccessToken = jwtResult.AccessToken,
                RefreshToken = jwtResult.RefreshToken.TokenString
            });
        }
        catch (SecurityTokenException e)
        {
            return Unauthorized(e.Message);
        }
    }

    [HttpPost("impersonation")]
    [Authorize(Roles = UserRoles.Admin)]
    public ActionResult Impersonate([FromBody] ImpersonationRequest request)
    {
        var userName = User.Identity?.Name!;
        logger.LogInformation("User [{userName}] is trying to impersonate [{anotherUserName}].", userName, request.UserName);

        var impersonatedRole = GetRole(request.UserName);
        if (string.IsNullOrWhiteSpace(impersonatedRole))
        {
            logger.LogInformation("User [{userName}] failed to impersonate [{anotherUserName}] due to the target user not found.", userName, request.UserName);
            return BadRequest($"The target user [{request.UserName}] is not found.");
        }
        if (impersonatedRole == UserRoles.Admin)
        {
            logger.LogInformation("User [{userName}] is not allowed to impersonate another Admin.", userName);
            return BadRequest("This action is not supported.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name,request.UserName),
            new Claim(ClaimTypes.Role, impersonatedRole),
            new Claim("OriginalUserName", userName)
        };

        var jwtResult = jwtAuthManager.GenerateTokens(request.UserName, claims, DateTime.Now);
        logger.LogInformation("User [{request.UserName}] is impersonating [{anotherUserName}] in the system.", userName, request.UserName);
        return Ok(new LoginResult
        {
            UserName = request.UserName,
            Role = impersonatedRole,
            OriginalUserName = userName,
            AccessToken = jwtResult.AccessToken,
            RefreshToken = jwtResult.RefreshToken.TokenString
        });
    }

    [HttpPost("stop-impersonation")]
    [Authorize]
    public ActionResult StopImpersonation()
    {
        var userName = User.Identity?.Name!;
        var originalUserName = User.FindFirst("OriginalUserName")?.Value;
        if (string.IsNullOrWhiteSpace(originalUserName))
        {
            return BadRequest("You are not impersonating anyone.");
        }
        logger.LogInformation("User [{originalUserName}] is trying to stop impersonate [{userName}].", originalUserName, userName);

        var role = GetRole(originalUserName);
        var claims = new[]
        {
            new Claim(ClaimTypes.Name,originalUserName),
            new Claim(ClaimTypes.Role, role)
        };

        var jwtResult = jwtAuthManager.GenerateTokens(originalUserName, claims, DateTime.Now);
        logger.LogInformation("User [{originalUserName}] has stopped impersonation.", originalUserName);
        return Ok(new LoginResult
        {
            UserName = originalUserName,
            Role = role,
            OriginalUserName = string.Empty,
            AccessToken = jwtResult.AccessToken,
            RefreshToken = jwtResult.RefreshToken.TokenString
        });
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public ActionResult Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Invalid request.");
        }

        if (context.Users.Any(x => x.Email == request.Email))
        {
            return Conflict("Email already exists.");
        }

        string hashedPassword = PasswordHasher.HashPassword(request.Password);

        var newUser = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = hashedPassword,
            Role = "Author",
            CreatedAt = DateTime.UtcNow
        };

        context.Users.Add(newUser);
        context.SaveChanges();

        return Ok("Account registered successfully.");
    }

    [Authorize]
    [HttpPost("change-password")]
    public ActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest("Invalid request.");
        }

        var userEmail = User.Identity?.Name;
        var user = context.Users.FirstOrDefault(x => x.Email == userEmail);

        if (user == null)
        {
            return NotFound("User not found.");
        }

        if (!PasswordHasher.VerifyPassword(request.OldPassword, user.PasswordHash))
        {
            return BadRequest("Old password is incorrect.");
        }

        user.PasswordHash = PasswordHasher.HashPassword(request.NewPassword);
        context.SaveChanges();

        return Ok("Password changed successfully.");
    }

    string GetRole(string userName)
    {
        if (userName.Contains("admin"))
        {
            return "Admin";
        }
        else
        {
            return "User";
        }

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
    [JsonPropertyName("username")] public string UserName { get; set; } = string.Empty;

    [JsonPropertyName("role")] public string Role { get; set; } = string.Empty;

    [JsonPropertyName("originalUserName")] public string OriginalUserName { get; set; } = string.Empty;

    [JsonPropertyName("accessToken")] public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refreshToken")] public string RefreshToken { get; set; } = string.Empty;
}

public class RefreshTokenRequest
{
    [JsonPropertyName("refreshToken")] public string RefreshToken { get; set; } = string.Empty;
}

public class ImpersonationRequest
{
    [JsonPropertyName("username")] public string UserName { get; set; } = string.Empty;
}