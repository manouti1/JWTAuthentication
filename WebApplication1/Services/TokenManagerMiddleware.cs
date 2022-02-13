namespace WebApplication1.Services
{
    using System.Net;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;

    public class TokenManagerMiddleware : IMiddleware
    {
        readonly ITokenManager _tokenManager;

        public TokenManagerMiddleware(ITokenManager tokenManager)
        {
            _tokenManager = tokenManager;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            if (await _tokenManager.IsCurrentActiveToken())
            {
                await next(context);

                return;
            }

            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        }
    }
}