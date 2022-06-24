using System.Text.Json.Serialization;

namespace AutenticacaoJwt.Api.ViewModels
{
    public class LoginRequestViewModel
    {
        [JsonPropertyName("usuario")]
        public string Usuario { get; set; }

        [JsonPropertyName("senha")]
        public string Senha { get; set; }
    }
}
