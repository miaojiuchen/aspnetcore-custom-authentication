namespace Auth.Authentication
{
    public class User
    {
        public string Name { get; set; }
        public string PasswordHash { get; set; }
        public bool IsAdmin { get; set; }
    }
}