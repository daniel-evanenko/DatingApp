using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiContorller
    {
        private readonly DataContext _Context;
        private readonly ITokenService _TokenService;
        public AccountController(DataContext context,ITokenService TokenService)
        {
            _TokenService = TokenService;
            _Context = context;

        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDTOs registerDto){
            
            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();
            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
             
             _Context.User.Add(user);
             await _Context.SaveChangesAsync();

             return new UserDto
             {
                 Username = user.UserName,
                 Token = _TokenService.CreateToken(user)
             };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            var user = await _Context.User.SingleOrDefaultAsync( x => x.UserName == loginDto.Username);
            if(user == null) return Unauthorized("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i=0; i<computeHash.Length; i++)
            {
                if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }
            
             return new UserDto
             {
                 Username = user.UserName,
                 Token = _TokenService.CreateToken(user)
             };
        }

        private async Task<bool> UserExists(String username)
        {
            return await _Context.User.AnyAsync(x => x.UserName == username.ToLower());
        }
    }


}