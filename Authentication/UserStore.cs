using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Auth.Authentication
{
    public class UserStore : IUserStore<User>
    {
        private Dictionary<string, User> Users = new Dictionary<string, User>(StringComparer.OrdinalIgnoreCase)
        {
            {"Admin", new User{Name = "Admin", IsAdmin = true}},
            {"Jiuchenm", new User{Name = "Jiuchenm", IsAdmin = false}},
        };

        private Dictionary<string, string> PasswordMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            {"Admin", "!@#$%^"},
            {"Jiuchenm", "123456"},
        };

        public Task<IdentityResult> CreateAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> DeleteAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<User> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<User> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            var user = Users[normalizedUserName];
            user.PasswordHash = new PasswordHasher<User>().HashPassword(user, PasswordMap[normalizedUserName]);
            return Task.FromResult(user);
        }

        public Task<string> GetNormalizedUserNameAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetUserIdAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<string> GetUserNameAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetNormalizedUserNameAsync(User user, string normalizedName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task SetUserNameAsync(User user, string userName, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public Task<IdentityResult> UpdateAsync(User user, CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {

        }
    }
}