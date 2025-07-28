using auth_service.Services;
using auth_service.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace auth_service;

public class Program
{
    public static void Main(string[] args)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Logging.AddDebug();

        builder.Services.AddHttpContextAccessor();

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseMySql(
                builder.Configuration.GetConnectionString("DefaultConnection"),
                new MySqlServerVersion(new Version(8, 0, 21))
            ));

        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(policy =>
            {
                policy
                    .WithOrigins("http://localhost:3000")
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        // Проверка конфигурации JWT
        string? jwtIssuer = builder.Configuration["Jwt:Issuer"];
        string? jwtAudience = builder.Configuration["Jwt:Audience"];
        string? jwtKey = builder.Configuration["Jwt:SecretKey"];

        if (string.IsNullOrWhiteSpace(jwtKey))
        {
            throw new Exception(
                "JWT SecretKey is not configured! Please set 'Jwt:SecretKey' in appsettings.json or environment variables.");
        }

        if (string.IsNullOrWhiteSpace(jwtIssuer))
        {
            throw new Exception(
                "JWT Issuer is not configured! Please set 'Jwt:Issuer' in appsettings.json or environment variables.");
        }

        if (string.IsNullOrWhiteSpace(jwtAudience))
        {
            throw new Exception(
                "JWT Audience is not configured! Please set 'Jwt:Audience' in appsettings.json or environment variables.");
        }

        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,

                    ValidIssuer = jwtIssuer,
                    ValidAudience = jwtAudience,
                    IssuerSigningKey = signingKey
                };

                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        // Смотрим токен в header, если нет, пытаемся взять из куков
                        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
                        if (string.IsNullOrEmpty(authHeader))
                        {
                            var tokenFromCookie = context.Request.Cookies["auth_token"];
                            if (!string.IsNullOrEmpty(tokenFromCookie))
                            {
                                context.Token = tokenFromCookie;
                            }
                        }

                        return Task.CompletedTask;
                    },

                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine("JWT Authentication failed: " + context.Exception.Message);
                        return Task.CompletedTask;
                    },

                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        return Task.CompletedTask;
                    }
                };
            });

        builder.Services.AddAuthorization();
        builder.Services.AddScoped<IAuthService, AuthService>();
        builder.Services.AddScoped<ITokenService, TokenService>();
        builder.Services.AddScoped<IPasswordService, PasswordService>();

        WebApplication app = builder.Build();

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseCors();
        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}