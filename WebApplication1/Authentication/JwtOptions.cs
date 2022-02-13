namespace WebApplication1.Authentication
{
    public class JwtOptions
    {
        public string Secret { get; set; }
        public int ExpiryMinutes { get; set; }
        public string ValidAudience { get; set; }
        public string ValidIssuer { get; set; }
    }
}