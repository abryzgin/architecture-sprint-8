using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Добавляем консольное логирование
builder.Logging.AddConsole();

// Читаем переменные окружения с проверкой на null
var keycloakServerUrl = Environment.GetEnvironmentVariable("KEYCLOAK_SERVER_URL") ?? "";
var keycloakRealm = Environment.GetEnvironmentVariable("KEYCLOAK_REALM") ?? "";
var keycloakClientId = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID") ?? "";
var keycloakAllowedRole = Environment.GetEnvironmentVariable("KEYCLOAK_ALLOWED_ROLE") ?? "";

// Регистрируем аутентификацию JWT через Keycloak
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"{keycloakServerUrl}/realms/{keycloakRealm}";
        options.Audience = keycloakClientId;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false
        };
        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var log = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                log.LogError("Ошибка аутентификации: {Error}", context.Exception.Message);
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                var log = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                var claims = string.Join(", ", context.Principal.Claims.Select(c => $"{c.Type}: {c.Value}"));
                log.LogInformation("Токен проверен. Утверждения: {Claims}", claims);
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                var log = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                log.LogWarning("Событие OnChallenge вызвано. Ошибка: {Error}, Описание: {Description}",
                    context.Error, context.ErrorDescription);
                return Task.CompletedTask;
            }
        };
    });

// Регистрируем политику авторизации, проверяющую наличие требуемой роли
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AllowedRolePolicy", policy =>
        policy.RequireAssertion(context =>
        {
            // Пытаемся получить логгер из контекста запроса
            var log = context.Resource switch
            {
                HttpContext httpContext => httpContext.RequestServices.GetRequiredService<ILogger<Program>>(),
                _ => LoggerFactory.Create(logging => logging.AddConsole()).CreateLogger("Default")
            };

            var realmAccessClaim = context.User.FindFirst("realm_access");
            if (realmAccessClaim == null)
            {
                log.LogWarning("Отсутствует claim 'realm_access' в токене.");
                return false;
            }

            try
            {
                var jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                };

                var realmAccess = JsonSerializer.Deserialize<RealmAccess>(
                    realmAccessClaim.Value,
                    jsonOptions
                );
                
                if (realmAccess?.Roles == null)
                {
                    log.LogWarning("В claim 'realm_access' не обнаружены роли.");
                    return false;
                }

                bool hasRole = realmAccess.Roles.Contains(keycloakAllowedRole);
                if (!hasRole)
                {
                    log.LogWarning("У пользователя отсутствует требуемая роль: {Role}.", keycloakAllowedRole);
                }
                else
                {
                    log.LogInformation("У пользователя имеется требуемая роль: {Role}.", keycloakAllowedRole);
                }
                return hasRole;
            }
            catch (Exception ex)
            {
                log.LogError("Ошибка десериализации claim 'realm_access': {Error}", ex.Message);
                return false;
            }
        })
    );
});

// Регистрируем CORS (разрешены запросы из любых источников)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(corsBuilder =>
    {
        corsBuilder.AllowAnyOrigin()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
    });
});

// Важно: регистрировать аутентификацию и авторизацию до создания приложения
var app = builder.Build();

// Получаем логгер из приложения
var logger = app.Logger;

// Логируем полученные переменные окружения
logger.LogInformation("URL сервера Keycloak: {Url}", keycloakServerUrl);
logger.LogInformation("Реалм Keycloak: {Realm}", keycloakRealm);
logger.LogInformation("ID клиента Keycloak: {ClientId}", keycloakClientId);
logger.LogInformation("Разрешённая роль Keycloak: {Role}", keycloakAllowedRole);

// Middleware для логирования входящих запросов
app.Use(async (context, next) =>
{
    var log = context.RequestServices.GetRequiredService<ILogger<Program>>();
    log.LogInformation("Входящий запрос: {Method} {Path}", context.Request.Method, context.Request.Path);
    if (context.Request.Headers.ContainsKey("Authorization"))
    {
        log.LogInformation("Заголовок Authorization: {Auth}", context.Request.Headers["Authorization"]);
    }
    await next.Invoke();
});

app.UseStatusCodePages(async context =>
{
    if (context.HttpContext.Response.StatusCode == 403)
    {
        context.HttpContext.Response.ContentType = "text/plain";
        await context.HttpContext.Response.WriteAsync("У вас недостаточно прав для доступа к этому ресурсу.");
    }
});

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Определяем endpoint, защищённый политикой "AllowedRolePolicy"
app.MapGet("/reports", () => "Держи свой отчет!")
   .RequireAuthorization("AllowedRolePolicy");

app.Run();

// Класс для десериализации claim "realm_access"
record RealmAccess(List<string> Roles);
