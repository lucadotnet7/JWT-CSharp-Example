using JWTImplementation.API.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTImplementation.API.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class IdentityController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public IdentityController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public IActionResult Login([FromBody] TestUserModel user)
        {
            IActionResult response = Unauthorized();
            var testUserModel = ValidUser(user);
            if (testUserModel != null)
            {
                var token = GenerateJsonWebToken(testUserModel);
                response = Ok(new { token = token });
            }
            return response;
        }

        [Authorize]
        [HttpGet("Secret")]
        public IActionResult Secret(ClaimsPrincipal user) 
        {
            return Ok($"Hello {user.Identity?.Name}. This is your secret.");
        }


        [Authorize(Policy = IdentityPolicy.AdminPolicyName)]
        [HttpGet("UsingPolicy")]
        public IActionResult UsingPolicy()
        {
            return Ok("You're admin!");
        }

        #region Private Methods
        private TestUserModel? ValidUser(TestUserModel user)
        {
            if (user.Email == "testemail@email.com")
                return new TestUserModel 
                { 
                    Email = user.Email,
                    Password = Guid.NewGuid().ToString(),
                };

            return null;
        }

        //Is not a good practice genera the jwt in the controller
        //but for example purpose I created it here.
        private string GenerateJsonWebToken(TestUserModel user)
        {
            var securityKey = Encoding.UTF8.GetBytes(_configuration["Authorization:Bearer:Key"]!);
            var credentials = new SigningCredentials(new SymmetricSecurityKey(securityKey), SecurityAlgorithms.HmacSha256Signature);
            var claims = new Claim[]
            {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(IdentityPolicy.AdminClaimName, "true") //It's only for test purpose
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = _configuration["Authorization:Bearer:Issuer"],
                Audience = _configuration["Authorization:Bearer:Audience"],
                SigningCredentials = credentials,
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
        #endregion
    }
}
