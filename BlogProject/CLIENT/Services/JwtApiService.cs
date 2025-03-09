using System.Net.Http.Headers;
using System.Text.Json;
using System.Text;

namespace CLIENT.Services
{
    public class JwtApiService
    {
        private readonly HttpClient _client;

        public JwtApiService(HttpClient client)
        {
            _client = client;
        }

        public async Task<LoginResult?> LoginAsync(string username, string password)
        {
            var loginRequest = new { username, password };
            var content = new StringContent(JsonSerializer.Serialize(loginRequest), Encoding.UTF8, "application/json");

            var response = await _client.PostAsync("api/account/login", content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<LoginResult>(responseContent);
            }

            return null;
        }

        public async Task<string?> GetUserInfoAsync(string accessToken)
        {
            _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var response = await _client.GetAsync("api/account/user");

            if (response.IsSuccessStatusCode)
            {
                return await response.Content.ReadAsStringAsync();
            }

            return null;
        }

        public async Task<LoginResult?> RefreshTokenAsync(string refreshToken)
        {
            var refreshRequest = new { refreshToken };
            var content = new StringContent(JsonSerializer.Serialize(refreshRequest), Encoding.UTF8, "application/json");
            var response = await _client.PostAsync("api/account/refresh-token", content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<LoginResult>(responseContent);
            }

            return null;
        }
    }

    public class LoginResult
    {
        public string UserName { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }

    public static class UserRoles
    {
        public const string Admin = nameof(Admin);
        public const string BasicUser = nameof(BasicUser);
    }
}
