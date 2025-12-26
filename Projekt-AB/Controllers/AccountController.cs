using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Projekt_AB.Models;
using System.Text;
using System.Text.Encodings.Web;
using QRCoder;

namespace Projekt_AB.Controllers;

public class AccountController : Controller
{
    private readonly UserManager<AppUser> _userManager;
    private readonly SignInManager<AppUser> _signInManager;
    private readonly UrlEncoder _urlEncoder;

    public AccountController(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _urlEncoder = urlEncoder;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(RegisterViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = new AppUser { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return RedirectToAction("EnableAuthenticator");
            }

            foreach (var error in result.Errors)
            {
                // Simple translation for common errors, or pass through
                var description = error.Description;
                if (error.Code == "DuplicateUserName") description = "Ten adres email jest już zajęty.";
                if (error.Code == "PasswordTooShort") description = "Hasło musi mieć co najmniej 8 znaków.";
                if (error.Code == "PasswordRequiresNonAlphanumeric") description = "Hasło musi zawierać znak specjalny.";
                if (error.Code == "PasswordRequiresDigit") description = "Hasło musi zawierać cyfrę.";
                if (error.Code == "PasswordRequiresUpper") description = "Hasło musi zawierać dużą literę.";
                
                ModelState.AddModelError(string.Empty, description);
            }
        }
        return View(model);
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (!user.TwoFactorEnabled)
                {
                    return RedirectToAction("EnableAuthenticator");
                }
                return RedirectToAction("Index", "Vault");
            }
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction("LoginWith2fa");
            }
            
            ModelState.AddModelError(string.Empty, "Nieprawidłowa próba logowania.");
        }
        return View(model);
    }

    [HttpGet]
    public async Task<IActionResult> LoginWith2fa(bool rememberMe)
    {
        var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            return RedirectToAction("Login");
        }
        return View(new LoginWith2faViewModel { RememberMe = rememberMe });
    }

    [HttpPost]
    public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(model.TwoFactorCode, model.RememberMe, false);

        if (result.Succeeded)
        {
            return RedirectToAction("Index", "Vault");
        }
        
        ModelState.AddModelError(string.Empty, "Nieprawidłowy kod weryfikacyjny.");
        return View(model);
    }

    [Authorize]
    [HttpGet]
    public async Task<IActionResult> EnableAuthenticator()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        await LoadSharedKeyAndQrCodeUriAsync(user);

        return View(new MfaSetupViewModel { SharedKey = await _userManager.GetAuthenticatorKeyAsync(user), AuthenticatorUri = await GenerateQrCodeUri(user) });
    }

    [Authorize]
    [HttpPost]
    public async Task<IActionResult> EnableAuthenticator(VerifyMfaViewModel model)
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return NotFound();

        if (!ModelState.IsValid)
        {
            await LoadSharedKeyAndQrCodeUriAsync(user);
            return View(new MfaSetupViewModel { SharedKey = await _userManager.GetAuthenticatorKeyAsync(user), AuthenticatorUri = await GenerateQrCodeUri(user) });
        }

        var verificationCode = model.Code.Replace(" ", string.Empty).Replace("-", string.Empty);
        var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2faTokenValid)
        {
            ModelState.AddModelError("Code", "Kod weryfikacyjny jest nieprawidłowy.");
            await LoadSharedKeyAndQrCodeUriAsync(user);
            return View(new MfaSetupViewModel { SharedKey = await _userManager.GetAuthenticatorKeyAsync(user), AuthenticatorUri = await GenerateQrCodeUri(user) });
        }

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        return RedirectToAction("Index", "Vault");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();
        return RedirectToAction("Login");
    }

    private async Task LoadSharedKeyAndQrCodeUriAsync(AppUser user)
    {
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
        }
    }

    private async Task<string> GenerateQrCodeUri(AppUser user)
    {
        var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
        return string.Format(
            "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6",
            _urlEncoder.Encode("MenadzerHasel"),
            _urlEncoder.Encode(user.Email),
            unformattedKey);
    }
}
