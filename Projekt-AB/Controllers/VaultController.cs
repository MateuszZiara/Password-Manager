using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Projekt_AB.Data;
using Projekt_AB.Models;
using Projekt_AB.Services;

namespace Projekt_AB.Controllers;

[Authorize]
public class VaultController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<AppUser> _userManager;
    private readonly EncryptionService _encryptionService;

    public VaultController(ApplicationDbContext context, UserManager<AppUser> userManager, EncryptionService encryptionService)
    {
        _context = context;
        _userManager = userManager;
        _encryptionService = encryptionService;
    }

    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return RedirectToAction("Login", "Account");

        // Force check if MFA is enabled
        if (!user.TwoFactorEnabled)
        {
            return RedirectToAction("EnableAuthenticator", "Account");
        }

        var items = await _context.PasswordEntries
            .Where(p => p.UserId == user.Id)
            .ToListAsync();

        var viewModels = items.Select(i => new VaultItemViewModel
        {
            Id = i.Id,
            ServiceName = i.ServiceName,
            Username = i.Username,
            Password = _encryptionService.Decrypt(i.EncryptedPassword, i.IV)
        }).ToList();

        return View(viewModels);
    }

    [HttpPost]
    public async Task<IActionResult> Add(VaultItemViewModel model)
    {
        if (ModelState.IsValid)
        {
            var user = await _userManager.GetUserAsync(User);
            var (encrypted, iv) = _encryptionService.Encrypt(model.Password);

            var entry = new PasswordEntry
            {
                UserId = user.Id,
                ServiceName = model.ServiceName,
                Username = model.Username,
                EncryptedPassword = encrypted,
                IV = iv
            };

            _context.PasswordEntries.Add(entry);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Delete(int id)
    {
        var user = await _userManager.GetUserAsync(User);
        var entry = await _context.PasswordEntries.FirstOrDefaultAsync(e => e.Id == id && e.UserId == user.Id);
        
        if (entry != null)
        {
            _context.PasswordEntries.Remove(entry);
            await _context.SaveChangesAsync();
        }
        return RedirectToAction(nameof(Index));
    }
}

