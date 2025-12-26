namespace Projekt_AB.Models;

public class PasswordEntry
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public AppUser User { get; set; }
    public string ServiceName { get; set; }
    public string Username { get; set; }
    public string EncryptedPassword { get; set; }
    public string IV { get; set; }
}

