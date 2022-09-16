using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using VerifyEmailForgotPass.Data;
using VerifyEmailForgotPass.Models;
using System.Text;
using VerifyEmailForgotPass.Entities;
using Microsoft.EntityFrameworkCore;

namespace VerifyEmailForgotPass.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly DataContext _db;

        public UserController(DataContext db)
        {
            _db = db;
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register(Register newUser)
        {
            if (_db.Users.Any(x => x.Email == newUser.Email))
                return BadRequest("User already exists");

            CreatePasswordHash(newUser.Password, out byte[] passwordHash, out byte[] passwordSalt);

            var user = new User
            {
                Email = newUser.Email,
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                VerificationToken = CreateRandomToken()
            };

            _db.Users.Add(user);  
            await _db.SaveChangesAsync();

            return Ok(newUser);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(Login login)
        {
            var user = await _db.Users.FirstOrDefaultAsync(x => x.Email == login.Email);
            if (user == null)
                return BadRequest("User not found");

            if (!VerifyPasswordHash(login.Password, user.PasswordHash, user.PasswordSalt))
                return BadRequest("Invalid credentials");

            if (user.VerifiedAt == null)
                return BadRequest("Not verified");

            return Ok($"Welcome back, {user.Email}");
        }

        [HttpPost("verify")]
        public async Task<IActionResult> Verify(string token)
        {
            var user = await _db.Users.FirstOrDefaultAsync(x => x.VerificationToken == token);

            if (user == null)
                return BadRequest("Invalid Token");

            user.VerifiedAt = DateTime.Now;
            await _db.SaveChangesAsync();

            return Ok("User verified");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _db.Users.FirstOrDefaultAsync(x => x.Email == email);

            if(user == null)
                return BadRequest("User not found");

            user.PasswordResetToken = CreateRandomToken();
            user.ResetTokenExpires = DateTime.Now.AddDays(1);
            await _db.SaveChangesAsync();

            return Ok("You may now reset your password");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(Reset request)
        {
            var user = await _db.Users.FirstOrDefaultAsync(x => x.PasswordResetToken == request.Token);

            if (user == null || user.ResetTokenExpires < DateTime.Now)
                return BadRequest("Invalid Token");

            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            user.PasswordResetToken = null;
            user.ResetTokenExpires = null;

            await _db.SaveChangesAsync();

            return Ok("Password successfully reset.");
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));

                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateRandomToken()
        {
            return Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }
}
