using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CMCS.Data;
using CMCS.Models;
using CMCS.Models.ViewModels;
using System.Security.Cryptography;
using System.Text;
using Claim = CMCS.Models.Claim;

namespace CMCS.Controllers
{
    [Authorize(Roles = "HR")]
    public class HRController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<HRController> _logger;

        public HRController(ApplicationDbContext context, ILogger<HRController> logger)
        {
            _context = context;
            _logger = logger;
        }

        // ============================================================
        // HR DASHBOARD
        // ============================================================
        public async Task<IActionResult> Dashboard()
        {
            try
            {
                var ready = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.APPROVED_FINAL && c.IsActive)
                    .Include(c => c.Lecturer)
                    .OrderByDescending(c => c.LastModifiedDate)
                    .ToListAsync();

                var paid = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.PAID && c.IsActive)
                    .Include(c => c.Lecturer)
                    .ToListAsync();

                var now = DateTime.Now;

                var thisMonthPaid = paid.Where(c =>
                    c.LastModifiedDate.Month == now.Month &&
                    c.LastModifiedDate.Year == now.Year);

                ViewBag.TotalForPayment = ready.Count;
                ViewBag.TotalAmount = ready.Sum(c => c.TotalAmount);
                ViewBag.ActiveLecturers = await _context.Users.Where(u => u.Role == UserRole.LECTURER && u.IsActive).CountAsync();
                ViewBag.ThisMonthPaid = thisMonthPaid.Count();
                ViewBag.ThisMonthAmount = thisMonthPaid.Sum(c => c.TotalAmount);

                return View(ready);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Dashboard failed");
                TempData["ErrorMessage"] = "Error loading dashboard.";
                return View(new List<Claim>());
            }
        }

        // ============================================================
        // MANAGE USERS
        // ============================================================
        public async Task<IActionResult> ManageUsers()
        {
            var users = await _context.Users
                .OrderBy(u => u.LastName)
                .ThenBy(u => u.FirstName)
                .ToListAsync();

            return View(users);
        }

        // ============================================================
        // CREATE USER (HR ONLY)
        // ============================================================
        public IActionResult CreateUser() => View();

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> CreateUser(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            if (await _context.Users.AnyAsync(u => u.Email == model.Email))
            {
                ModelState.AddModelError("Email", "This email already exists.");
                return View(model);
            }

            // Temporary password if none provided
            string plainPassword = string.IsNullOrWhiteSpace(model.Password)
                ? GenerateTemporaryPassword()
                : model.Password;

            string hashedPassword = HashPasswordConsistent(plainPassword);

            var user = new User
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                Password = hashedPassword,
                Role = model.Role,
                PhoneNumber = model.PhoneNumber,
                Department = model.Department,
                EmployeeNumber = model.EmployeeNumber,
                HourlyRate = model.HourlyRate ?? 0,
                CreatedDate = DateTime.Now,
                LastModifiedDate = DateTime.Now,
                IsActive = true
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] =
                $"User created successfully! Login Email: {user.Email} | Temporary Password: {plainPassword}";

            return RedirectToAction(nameof(ManageUsers));
        }

        // ============================================================
        // EDIT USER
        // ============================================================
        public async Task<IActionResult> EditUser(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction(nameof(ManageUsers));
            }

            var vm = new RegisterViewModel
            {
                UserId = user.UserId,
                FirstName = user.FirstName,
                LastName = user.LastName,
                Email = user.Email,
                Role = user.Role,
                PhoneNumber = user.PhoneNumber,
                Department = user.Department,
                EmployeeNumber = user.EmployeeNumber,
                HourlyRate = user.HourlyRate
            };

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(int id, RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction(nameof(ManageUsers));
            }

            user.FirstName = model.FirstName;
            user.LastName = model.LastName;
            user.Email = model.Email;
            user.Role = model.Role;
            user.PhoneNumber = model.PhoneNumber;
            user.Department = model.Department;
            user.EmployeeNumber = model.EmployeeNumber;
            user.HourlyRate = model.HourlyRate ?? 0;
            user.LastModifiedDate = DateTime.Now;

            if (!string.IsNullOrWhiteSpace(model.Password))
                user.Password = HashPasswordConsistent(model.Password);

            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "User updated successfully.";
            return RedirectToAction(nameof(ManageUsers));
        }

        // ============================================================
        // TOGGLE ACTIVE / INACTIVE
        // ============================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleLecturerStatus(int lecturerId)
        {
            var user = await _context.Users.FindAsync(lecturerId);

            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction(nameof(ManageUsers));
            }

            user.IsActive = !user.IsActive;
            user.LastModifiedDate = DateTime.Now;

            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] =
                $"{user.FirstName} {user.LastName} is now {(user.IsActive ? "Active" : "Inactive")}.";

            return RedirectToAction(nameof(ManageUsers));
        }

        // ============================================================
        // DELETE USER
        // ============================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _context.Users
                .Include(u => u.Claims)
                .FirstOrDefaultAsync(u => u.UserId == id);

            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction(nameof(ManageUsers));
            }

            if (user.Claims.Any())
            {
                TempData["ErrorMessage"] =
                    "Cannot delete user because they have existing claims.";
                return RedirectToAction(nameof(ManageUsers));
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = "User deleted.";
            return RedirectToAction(nameof(ManageUsers));
        }

        // ============================================================
        // CLAIM PAYMENT ACTIONS
        // ============================================================
        [HttpPost]
        public async Task<IActionResult> MarkAsPaid(int claimId)
        {
            var claim = await _context.Claims.FindAsync(claimId);

            if (claim == null)
            {
                TempData["ErrorMessage"] = "Claim not found.";
                return RedirectToAction(nameof(Dashboard));
            }

            claim.Status = ClaimStatus.PAID;
            claim.LastModifiedDate = DateTime.Now;

            await _context.SaveChangesAsync();
            TempData["SuccessMessage"] = "Claim marked as paid.";

            return RedirectToAction(nameof(Dashboard));
        }

        [HttpPost]
        public async Task<IActionResult> MarkMultipleAsPaid(int[] claimIds)
        {
            var claims = await _context.Claims
                .Where(c => claimIds.Contains(c.ClaimId))
                .ToListAsync();

            foreach (var c in claims)
            {
                c.Status = ClaimStatus.PAID;
                c.LastModifiedDate = DateTime.Now;
            }

            await _context.SaveChangesAsync();

            TempData["SuccessMessage"] = $"{claims.Count} claim(s) marked as paid.";
            return RedirectToAction(nameof(Dashboard));
        }

        // ============================================================
        // PASSWORD HASHING — MUST MATCH AccountController EXACTLY
        // ============================================================
        private string HashPasswordConsistent(string password)
        {
            var key = Encoding.UTF8.GetBytes("YourSecureSecretKey123");
            using var hmac = new HMACSHA512(key);
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        private string GenerateTemporaryPassword(int length = 8)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$#%";
            var sb = new StringBuilder();
            using var rng = RandomNumberGenerator.Create();
            var buffer = new byte[4];

            while (sb.Length < length)
            {
                rng.GetBytes(buffer);
                sb.Append(chars[(int)(BitConverter.ToUInt32(buffer, 0) % chars.Length)]);
            }

            return sb.ToString();
        }
    }
}
