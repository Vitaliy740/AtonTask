using AtonTask.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using AtonTask.DTOs;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;

namespace AtonTask.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserContext _dbContext;
        public UserController(UserContext dbContext)
        {
            _dbContext = dbContext;
        }
        private bool CheckCredentials(string login, string password, out User user)
        {
            user = _dbContext.Users.SingleOrDefault(u => u.Login == login && u.Password == password);
            return user != null;
        }

        // Only admins or the user itself can access certain methods
        private bool IsAuthorized(User user, bool requireAdmin = false)
        {
            return user != null && (user.Admin || !requireAdmin)&& user.RevokedOn==DateTime.MinValue;
        }
        /// <summary>
        /// 5) Запрос списка всех активных (отсутствует RevokedOn) пользователей, список отсортирован по CreatedOn(Доступно Админам)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <returns></returns>
        [HttpGet("Get All Users")]
        public async Task<ActionResult<IEnumerable<User>>> GetUsers(string requesterLogin, string requesterPassword)
        {
            if (_dbContext.Users == null) 
            {   
                return NotFound("Database context is not available.");
            }
            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester, true))
            {
                return Unauthorized("You entered wrong password, or Login, or you are not Admin");
            }
            return await _dbContext.Users.Where(x => x.RevokedOn==DateTime.MinValue).OrderBy(x=>x.CreatedOn).ToArrayAsync();
        }
        /// <summary>
        /// 6) Запрос пользователя по логину, в списке долны быть имя, пол и дата рождения статус 
        /// активный или нет(Доступно Админам)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpGet("Get user by login: {login}")]
        public async Task<ActionResult> GetUserByLogin(string requesterLogin,string requesterPassword, string login)
        {
            if (_dbContext.Users == null)
            {
                return NotFound("Database context is not available.");
            }

            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester, true))
            {
                return Unauthorized("You entered wrong password, or Login, or you are not Admin");
            }

            var user = await _dbContext.Users.FirstOrDefaultAsync(x=>x.Login==login);
            if (user == null) 
            {
                return NotFound("No user With Login {login} found");
            }

            return Ok( new { user.Name,user.Gender, user.BirthDay,isActive=(user.RevokedOn!=DateTime.MinValue)});
        }
        /// <summary>
        /// Create
        ///1) Создание пользователя по логину, паролю, имени, полу и дате рождения + указание будет ли
        /// пользователь админом(Доступно Админам)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("Create user")]
        public async Task<ActionResult<User>> Create(string requesterLogin, string requesterPassword, [FromForm] UserCreationData user) 
        {
            if (_dbContext.Users == null)
            {
                return NotFound("Database context is not available.");
            }
            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester, true))
            {
                return Unauthorized("You entered wrong password, or Login, or you are not Admin");
            }
            bool userAlreadyExist = await _dbContext.Users.AnyAsync(x=>x.Login==user.NewLogin);
            if (userAlreadyExist) 
            {
                return BadRequest("Login {user.Login} is already taken");
            }
            try
            {
                User newUser = new User()
                {
                    Guid = Guid.NewGuid(),

                    Login = user.NewLogin,
                    Password = user.NewPassword,
                    Name = user.NewName,
                    Gender = (int)Enum.Parse(typeof(GenderType), user.NewGender.ToString()),
                    BirthDay = user.NewBirthDate,
                    Admin = user.Admin,
                    CreatedOn = DateTime.UtcNow,
                    CreatedBy = requesterLogin,
                    RevokedOn = DateTime.MinValue,
                    RevokedBy = ""

                };
                _dbContext.Users.Add(newUser);
                await _dbContext.SaveChangesAsync();
                return CreatedAtAction(nameof(GetUserByLogin), new { login = user.NewLogin }, user);
            }
            catch (Exception ex) 
            {
                return BadRequest(ex.Message);
            }


        }
        /// <summary>
        /// Update-1
        ///2) Изменение имени, пола или даты рождения пользователя(Может менять Администратор, либо
        ///лично пользователь, если он активен (отсутствует RevokedOn))
        ///3) Изменение пароля(Пароль может менять либо Администратор, либо лично пользователь, если
        ///он активен (отсутствует RevokedOn))
        ///4) Изменение логина(Логин может менять либо Администратор, либо лично пользователь, если
        ///он активен (отсутствует RevokedOn), логин должен оставаться уникальным)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <param name="login"></param>
        /// <param name="userUpdate"></param>
        /// <returns></returns>
        [HttpPut("Update user 1")]
        public async Task<IActionResult> UpdateOne(string requesterLogin, string requesterPassword, string login, [FromForm] UserUpdateData userUpdate)
        {
            if (_dbContext.Users == null)
            {
                return NotFound("Database context is not available.");
            }
            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester))
            {
                return Unauthorized("You entered wrong password, or Login, or you are not Admin");
            }
            var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Login == login);
            if (user == null)
            {
                return NotFound("User you trying to access is not exist");
            }
            if (! requester.Admin && requester.Login!=login) 
            {
                return Unauthorized("Only admins or the user themselves can update their details.");
            }
            user.Name = string.IsNullOrEmpty( userUpdate.NewName) ? user.Name : userUpdate.NewName;
            user.Gender = userUpdate.NewGender.HasValue ? (int)userUpdate.NewGender.Value : user.Gender;
            user.BirthDay = userUpdate.NewBirthDate ?? user.BirthDay;
            user.Password = string.IsNullOrEmpty(userUpdate.NewPassword) ? user.Password : userUpdate.NewPassword;
            if (!string.IsNullOrEmpty(userUpdate.NewLogin) && userUpdate.NewLogin != user.Login)
            {
                if (!await IsLoginUnique(userUpdate.NewLogin))
                {
                    return BadRequest("The new login is already taken.");
                }
                user.Login = userUpdate.NewLogin;
            }
            user.ModifiedOn = DateTime.UtcNow;
            user.ModifiedBy = requester.Login;
            _dbContext.Entry(user).State = EntityState.Modified;
            try
            {
                await _dbContext.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await UserAvailable(user.Guid))
                {
                    return NotFound("User not found.");
                }
                else
                {
                    throw;
                }
            }

            return Ok("User updated successfully.");
        }
        /// <summary>
        /// Update-2
        /// 10) Восстановление пользователя - Очистка полей(RevokedOn, RevokedBy) (Доступно Админам)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpPut("Restore user with login: {login}")]
        public async Task<IActionResult> UpdateTwo(string requesterLogin, string requesterPassword,string login) 
        {
            if (_dbContext.Users == null)
            {
                return NotFound("Database context is not available.");
            }
            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester, true))
            {
                return Unauthorized("You entered wrong password, or Login, or you are not Admin");
            }
            var user = await _dbContext.Users.FirstAsync(x => x.Login == login);
            if (user == null) 
            {
                return NotFound("User you trying to access is not exist");
            }
            if (user.RevokedOn == DateTime.MinValue) 
            {
                return BadRequest("User is not revoked and does not require restoration");
            }
            user.RevokedOn = DateTime.MinValue;
            user.RevokedBy = "";
            _dbContext.Entry(user).State = EntityState.Modified;
            try
            {
                await _dbContext.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!await UserAvailable(user.Guid))
                {
                    return NotFound("User not found.");
                }
                else
                {
                    throw;
                }
            }
            return Ok("User has been restored from soft delete");
        }
        /// <summary>
        /// Delete
        ///9) Удаление пользователя по логину полное или мягкое(При мягком удалении должна
        /// происходить простановка RevokedOn и RevokedBy) (Доступно Админам)
        /// </summary>
        /// <param name="requesterLogin"></param>
        /// <param name="requesterPassword"></param>
        /// <param name="hardDelete"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        [HttpDelete("Delete user(soft/hard){login}")]
        public async Task<IActionResult> Delete(string requesterLogin, string requesterPassword, [Required]bool hardDelete, string login)
        {
            if (_dbContext.Users == null)
            {
                return NotFound("Database context is not available.");
            }
            if (!CheckCredentials(requesterLogin, requesterPassword, out User requester) || !IsAuthorized(requester, true))
            {
                return Unauthorized();
            }
            var user = await _dbContext.Users.FirstAsync(x => x.Login == login);
            if (user == null) return NotFound("User you trying to delete is not exist");
            if (hardDelete)
            {
                _dbContext.Users.Remove(user);
                await _dbContext.SaveChangesAsync();
                return Ok();
            }
            if (user.RevokedOn == DateTime.MinValue)
            {
                user.RevokedBy = requesterLogin;
                user.RevokedOn = DateTime.UtcNow;
                _dbContext.Entry(user).State = EntityState.Modified;
                try
                {
                    await _dbContext.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!await UserAvailable(user.Guid))
                    {
                        return NotFound("User not found.");
                    }
                    else
                    {
                        throw;
                    }
                }
                return Ok("User has been revoked");
            }
            return BadRequest("User is already revoked");
        }
        private async Task<bool> UserAvailable(Guid guid) 
        {
            return await (_dbContext.Users?.AnyAsync(x => x.Guid == guid) ?? Task.FromResult(false));
        }
        private async Task<bool> IsLoginUnique(string login)
        {
            // Исключите текущего пользователя из проверки, если это обновление его данных
            return !await _dbContext.Users.AnyAsync(u => u.Login == login );
        }
    }
}
