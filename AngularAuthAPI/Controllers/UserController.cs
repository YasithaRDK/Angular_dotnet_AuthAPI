using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography;
using AngularAuthAPI.Models.Dto;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }

            var user = await _authContext.Users.
                FirstOrDefaultAsync(x => x.UserName == userObj.UserName);

            if (user == null)
            {

                return NotFound(new { Message = "User Not Found!" });
            }

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {

                return BadRequest(new { message = "Password is Incorrect" });
            }

            else
            {
                user.Token = CreateJWT(user);
                var newAccessToken = user.Token;
                var newRefreshToken = CreateRefreshToken();
                user.RefreshToken = newRefreshToken;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(5);
                await _authContext.SaveChangesAsync();
                return Ok(new TokenApiDto()
                {
                    AccessToken = newAccessToken,
                    RefreshToken = newRefreshToken
                }); 
            }
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] User userObj)
        {
            if (userObj == null)
            {

                return BadRequest();
            }

            //Check User Name
            if (await CheckUserNameExistAsync(userObj.UserName))
            {

                return BadRequest(new { message = "User name Already Exist!" });
            }

            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
            {

                return BadRequest(new { message = "Email Already Exist!" });
            }

            //Chech Password Strength
            var pass = CheckPasswordStrength(userObj.Password);

            if (!string.IsNullOrEmpty(pass))
            {

                return BadRequest(new { message = pass.ToString() });
            }
            else
            {
                userObj.Password = PasswordHasher.HashPassword(userObj.Password);
                userObj.Role = "User";
                userObj.Token = "";
                await _authContext.Users.AddAsync(userObj);
                await _authContext.SaveChangesAsync();
                return Ok(new
                {
                    Message = "User Registerd!"
                });
            }
        }

        private Task<bool> CheckUserNameExistAsync(string username)
            => _authContext.Users.AnyAsync(x => x.UserName == username);

        private Task<bool> CheckEmailExistAsync(string email)
    => _authContext.Users.AnyAsync(x => x.Email == email);

        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
            {

                sb.Append("Minimum password length shoulb be 8\n");
            }
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") 
                && Regex.IsMatch(password, "[0-9]")))
            {

                sb.Append("Password should be Alphanumeric\n");
            }
            if (!(Regex.IsMatch(password, @"[~`!@#$%\^\&\*\(\)\-_\+=\[\{\]\}\|\\;:'\""<\,>\.\?\/£]")))
            {
                sb.Append("Password should be special characters\n");
            }
            return sb.ToString();
        }

        private string CreateJWT(User user)
        {
            var jwtTokenHandeler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes("veryverysceret.....");

            var identity = new ClaimsIdentity(new Claim[] 
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{ user.UserName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(10),
                SigningCredentials = credentials
            };

            var token = jwtTokenHandeler.CreateToken(tokenDescriptor);

            return jwtTokenHandeler.WriteToken(token);
        }

        private string CreateRefreshToken()
        {
            var cryptoProvider = RandomNumberGenerator.Create();
            byte[] bytes = new byte[64];
            cryptoProvider.GetBytes(bytes);
            string refreshToken = Convert.ToBase64String(bytes);

            var tokenInUser = _authContext.Users
                .Any(a => a.RefreshToken == refreshToken);
            if (tokenInUser)
            {
                return CreateRefreshToken();
            }
            else
            {
                return refreshToken;
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpirdToken(string token)
        {
            var key = Encoding.ASCII.GetBytes("veryverysceret.....");
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("This is Invalid Token");
            }
            return principal;
        }

        [Authorize]
        [HttpGet("users")]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh(TokenApiDto tokenApiDto)
        {
            if(tokenApiDto is null)
            {
                return BadRequest("Invalid Client Token");
            }
            else
            {
                string accessToken = tokenApiDto.AccessToken;
                string refreshToken = tokenApiDto.RefreshToken;
                var principal = GetPrincipalFromExpirdToken(accessToken);
                var userName = principal.Identity.Name;
                var user = await _authContext.Users.FirstOrDefaultAsync(u => u.UserName == userName);
                if(user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                {
                    return BadRequest("Invalid Request");
                }
                else
                {
                    var newAccessToken = CreateJWT(user);
                    var newRefreshToken = CreateRefreshToken();
                    user.RefreshToken = newRefreshToken;
                    await _authContext.SaveChangesAsync();
                    return Ok(new TokenApiDto()
                    {
                        AccessToken = newAccessToken,
                        RefreshToken = newRefreshToken
                    });
                }
            }
        }
    }
}
