using System.ComponentModel.DataAnnotations;

namespace Projekt_AB.Models;

public class RegisterViewModel
{
    [Required(ErrorMessage = "Adres email jest wymagany.")]
    [EmailAddress(ErrorMessage = "Nieprawidłowy adres email.")]
    [Display(Name = "Adres Email")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Hasło jest wymagane.")]
    [DataType(DataType.Password)]
    [Display(Name = "Hasło")]
    public string Password { get; set; }

    [DataType(DataType.Password)]
    [Display(Name = "Potwierdź hasło")]
    [Compare("Password", ErrorMessage = "Hasło i potwierdzenie hasła nie są identyczne.")]
    public string ConfirmPassword { get; set; }
}

public class LoginViewModel
{
    [Required(ErrorMessage = "Adres email jest wymagany.")]
    [EmailAddress(ErrorMessage = "Nieprawidłowy adres email.")]
    [Display(Name = "Adres Email")]
    public string Email { get; set; }

    [Required(ErrorMessage = "Hasło jest wymagane.")]
    [DataType(DataType.Password)]
    [Display(Name = "Hasło")]
    public string Password { get; set; }
}

public class MfaSetupViewModel
{
    public string SharedKey { get; set; }
    public string AuthenticatorUri { get; set; }
}

public class VerifyMfaViewModel
{
    [Required(ErrorMessage = "Kod jest wymagany.")]
    [Display(Name = "Kod weryfikacyjny")]
    public string Code { get; set; }
}

public class LoginWith2faViewModel
{
    [Required(ErrorMessage = "Kod jest wymagany.")]
    [Display(Name = "Kod weryfikacyjny")]
    public string TwoFactorCode { get; set; }
    public bool RememberMe { get; set; }
}

public class VaultItemViewModel
{
    public int Id { get; set; }
    [Required(ErrorMessage = "Nazwa serwisu jest wymagana.")]
    [Display(Name = "Nazwa serwisu")]
    public string ServiceName { get; set; }
    [Required(ErrorMessage = "Nazwa użytkownika jest wymagana.")]
    [Display(Name = "Nazwa użytkownika")]
    public string Username { get; set; }
    [Required(ErrorMessage = "Hasło jest wymagane.")]
    [DataType(DataType.Password)]
    [Display(Name = "Hasło")]
    public string Password { get; set; }
}
