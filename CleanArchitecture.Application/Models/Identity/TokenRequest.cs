namespace CleanArchitecture.Application.Models.Identity
{
    public class TokenRequest
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }

    }
}
