using AutenticacaoJwt.Api.Extensions;
using AutenticacaoJwt.Api.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AutenticacaoJwt.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AutenticacaoController : ControllerBase
    {
        private readonly AppSettings appSettings;
        public AutenticacaoController(IOptions<AppSettings> appSettings)
        {
            this.appSettings = appSettings.Value;
        }

        [Authorize]
        [HttpGet("teste")]
        public IActionResult Teste()
        {
            return Ok(new { Mensagem = "Minha Api com autenticação JWT" });
        }

        [HttpPost("login")]
        public IActionResult Login(LoginRequestViewModel login)
        {
            // simulação de login
            if (login.Usuario != "teste@teste.com" || login.Senha != "teste-api@123")
            {
                return Unauthorized();
            }

            var response = GerarJwt(login.Usuario);

            return Ok(response);
        }

        private LoginResponseViewModel GerarJwt(string usuario)
        {
            var claims = new List<Claim>();

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, usuario));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpoachDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpoachDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(appSettings.Secret);
            
            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = appSettings.Emissor,
                Audience = appSettings.ValidoEm,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(appSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });

            var encodedToken = tokenHandler.WriteToken(token);
            var response = new LoginResponseViewModel
            {
                Usuario = usuario,
                Token = encodedToken
            };

            return response;
        }

        private static long ToUnixEpoachDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
