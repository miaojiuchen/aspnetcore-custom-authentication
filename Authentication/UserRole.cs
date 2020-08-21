using Microsoft.AspNetCore.Identity;

namespace Auth.Authentication
{
    public class UserRole : IdentityUserRole<int>
    {
        public int Id { get; set; }
    }
}