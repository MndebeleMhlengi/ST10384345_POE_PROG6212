using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using CMCS.Data;
using CMCS.Models;
using CMCS.Models.ViewModels;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Claim = System.Security.Claims.Claim;

namespace CMCS.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AccountController> _logger;

        public AccountController(ApplicationDbContext context, ILogger<AccountController> logger)
        {
            _context = context;
            _logger = logger;
        }

        // Registration disabled for public users
        public IActionResult Register()
        {
            TempData["InfoMessage"] = "User registration is handled by HR administrators.";
            return RedirectToAction("Login");
        }

        // GET: Login
        public IActionResult Login()
        {
            if (User.Identity?.IsAuthenticated == true)
            {
                return RedirectToAction("Dashboard", GetControllerByRole(GetUserRole()));
            }

            return View();
        }

        // POST: Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email == model.Email && u.IsActive);

            if (user == null)
            {
                ModelState.AddModelError("", "Invalid email or password.");
                return View(model);
            }

            // 🔥 Correct password verification (matches HRController hashing)
            if (!VerifyPassword(model.Password, user.Password))
            {
                ModelState.AddModelError("", "Invalid email or password.");
                return View(model);
            }

            // Update last login time
            user.LastLoginDate = DateTime.Now;
            await _context.SaveChangesAsync();

            // Create security claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role.ToString()),
                new Claim("FullName", $"{user.FirstName} {user.LastName}"),
                new Claim("Department", user.Department ?? "")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var authProperties = new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            // Save session values
            HttpContext.Session.SetString("UserId", user.UserId.ToString());
            HttpContext.Session.SetString("UserName", $"{user.FirstName} {user.LastName}");
            HttpContext.Session.SetString("UserRole", user.Role.ToString());
            HttpContext.Session.SetString("UserEmail", user.Email);

            TempData["SuccessMessage"] = $"Welcome {user.FirstName}!";

            return RedirectToAction("Dashboard", GetControllerByRole(user.Role));
        }

        // POST: Logout
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            HttpContext.Session.Clear();
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            TempData["SuccessMessage"] = "You have been logged out.";
            return RedirectToAction("Login");
        }

        // ACCESS DENIED
        public IActionResult AccessDenied()
        {
            ViewBag.Message = "You do not have permission to access this resource.";
            ViewBag.ReturnUrl = Request.Headers["Referer"].ToString();
            return View();
        }


        // ---------------------------------------------------------------
        // 🔐 PASSWORD HASHING — MUST MATCH HRController EXACTLY
        // ---------------------------------------------------------------

        private string HashPassword(string password)
        {
            // This key MUST match HRController.HashPasswordConsistent()
            var key = Encoding.UTF8.GetBytes("YourSecureSecretKey123");

            using (var hmac = new HMACSHA512(key))
            {
                byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hashBytes);
            }
        }

        private bool VerifyPassword(string password, string hashedPassword)
        {
            return HashPassword(password) == hashedPassword;
        }

        // ---------------------------------------------------------------
        // ROLE HELPERS
        // ---------------------------------------------------------------

        private UserRole GetUserRole()
        {
            var roleString = User.FindFirst(ClaimTypes.Role)?.Value;

            if (Enum.TryParse(roleString, out UserRole role))
                return role;

            return UserRole.LECTURER;
        }

        private string GetControllerByRole(UserRole role)
        {
            return role switch
            {
                UserRole.LECTURER => "Lecturer",
                UserRole.PROGRAMME_COORDINATOR => "ProgrammeCoordinator",
                UserRole.ACADEMIC_MANAGER => "AcademicManager",
                UserRole.HR => "HR",
                _ => "Home"
            };
        }
    }
}
