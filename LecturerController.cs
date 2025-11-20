using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CMCS.Data;
using CMCS.Models;
using CMCS.Models.ViewModels;
using System.Security.Claims;
using Claim = CMCS.Models.Claim;

namespace CMCS.Controllers
{
    [Authorize(Roles = "LECTURER")]
    public class LecturerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _environment;
        private readonly ILogger<LecturerController> _logger;

        // PART 3: Validation constant for maximum hours per month
        private const decimal MAX_HOURS_PER_MONTH = 180m;

        public LecturerController(ApplicationDbContext context, IWebHostEnvironment environment, ILogger<LecturerController> logger = null)
        {
            _context = context;
            _environment = environment;
            _logger = logger;
        }

        public async Task<IActionResult> Dashboard()
        {
            try
            {
                // PART 3: Validate session
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var user = await _context.Users.FindAsync(userId);

                if (user == null)
                {
                    TempData["ErrorMessage"] = "User not found. Please log in again.";
                    return RedirectToAction("Login", "Account");
                }

                var recentClaims = await _context.Claims
                    .Where(c => c.LecturerId == userId)
                    .OrderByDescending(c => c.SubmissionDate)
                    .Take(10)
                    .ToListAsync();

                var allUserClaims = _context.Claims.Where(c => c.LecturerId == userId);

                ViewBag.User = user;
                ViewBag.PendingClaims = await allUserClaims.CountAsync(c => c.Status == ClaimStatus.PENDING);
                ViewBag.ApprovedClaims = await allUserClaims.CountAsync(c => c.Status == ClaimStatus.APPROVED_FINAL);
                ViewBag.TotalClaims = await allUserClaims.CountAsync();

                return View(recentClaims);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Dashboard error for user");
                TempData["ErrorMessage"] = "Error loading dashboard. Please try again.";
                return View(new List<Claim>());
            }
        }

        // PART 3: Updated to pull hourly rate from user profile
        public async Task<IActionResult> SubmitClaim()
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var user = await _context.Users.FindAsync(userId);

                if (user == null)
                {
                    TempData["ErrorMessage"] = "User not found. Please log in again.";
                    return RedirectToAction("Dashboard");
                }

                // PART 3: Pre-populate with user's hourly rate from HR-managed profile
                var model = new ClaimSubmissionViewModel
                {
                    HourlyRate = user.HourlyRate, // Pulled from user profile
                    YearWorked = DateTime.Now.Year,
                    MonthWorked = DateTime.Now.Month
                };

                // Pass user info to view for display
                ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                ViewBag.LecturerRate = user.HourlyRate;
                ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;

                return View(model);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "SubmitClaim GET error");
                TempData["ErrorMessage"] = "Error loading claim form. Please try again.";
                return RedirectToAction("Dashboard");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SubmitClaim(ClaimSubmissionViewModel model)
        {
            var userId = 0;
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var user = await _context.Users.FindAsync(userId);

                if (user == null)
                {
                    TempData["ErrorMessage"] = "User not found. Please log in again.";
                    return RedirectToAction("Login", "Account");
                }

                // PART 3: Force hourly rate to be from user profile (HR-managed)
                model.HourlyRate = user.HourlyRate;

                // Remove ModelState validation for HourlyRate
                ModelState.Remove("HourlyRate");

                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList();
                    _logger?.LogWarning($"ModelState invalid: {string.Join(", ", errors)}");

                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                // PART 3: Enhanced validation - Check maximum hours per month
                if (model.HoursWorked > MAX_HOURS_PER_MONTH)
                {
                    ModelState.AddModelError("HoursWorked",
                        $"Hours worked cannot exceed {MAX_HOURS_PER_MONTH} hours per month. You entered {model.HoursWorked} hours.");

                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                // Standard validations
                if (model.HoursWorked <= 0 || model.HoursWorked > 500)
                {
                    ModelState.AddModelError("HoursWorked", "Hours worked must be between 0.1 and 500.");
                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                if (string.IsNullOrWhiteSpace(model.ModuleTaught))
                {
                    ModelState.AddModelError("ModuleTaught", "Module taught is required.");
                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                if (model.MonthWorked < 1 || model.MonthWorked > 12)
                {
                    ModelState.AddModelError("MonthWorked", "Please select a valid month.");
                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                if (model.YearWorked < 2020 || model.YearWorked > 2030)
                {
                    ModelState.AddModelError("YearWorked", "Year must be between 2020 and 2030.");
                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                var moduleTaught = model.ModuleTaught.Trim();
                var additionalNotes = string.IsNullOrWhiteSpace(model.AdditionalNotes)
                    ? null
                    : model.AdditionalNotes.Trim();

                // Check for duplicate claims
                var hasDuplicate = await _context.Claims
                    .AnyAsync(c =>
                        c.LecturerId == userId &&
                        c.MonthWorked == model.MonthWorked &&
                        c.YearWorked == model.YearWorked &&
                        c.ModuleTaught.ToLower() == moduleTaught.ToLower() &&
                        c.IsActive);

                if (hasDuplicate)
                {
                    var monthName = new DateTime(model.YearWorked, model.MonthWorked, 1).ToString("MMMM yyyy");
                    ModelState.AddModelError("", $"You have already submitted a claim for {moduleTaught} in {monthName}.");
                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                // Generate unique reference
                var timestamp = DateTime.Now.ToString("yyMMddHHmm");
                var uniqueId = Guid.NewGuid().ToString().Substring(0, 4).ToUpper();
                var claimReference = $"CLM-{timestamp}-{uniqueId}";

                if (claimReference.Length > 20)
                {
                    claimReference = claimReference.Substring(0, 20);
                    _logger?.LogWarning($"Claim reference truncated to 20 characters: {claimReference}");
                }

                var claim = new Claim
                {
                    LecturerId = userId,
                    MonthWorked = model.MonthWorked,
                    YearWorked = model.YearWorked,
                    HoursWorked = model.HoursWorked,
                    HourlyRate = user.HourlyRate, // PART 3: Use rate from user profile
                    ModuleTaught = moduleTaught,
                    AdditionalNotes = additionalNotes,
                    Status = ClaimStatus.PENDING,
                    SubmissionDate = DateTime.Now,
                    LastModifiedDate = DateTime.Now,
                    ClaimReference = claimReference,
                    IsActive = true
                };

                // PART 3: Auto-calculate total amount
                claim.TotalAmount = claim.HoursWorked * claim.HourlyRate;

                _logger?.LogInformation($"Creating claim: User={userId}, Hours={model.HoursWorked}, Rate={user.HourlyRate}, Total={claim.TotalAmount}, Reference={claimReference}");

                _context.Claims.Add(claim);

                try
                {
                    await _context.SaveChangesAsync();
                    _logger?.LogInformation($"Claim saved successfully with ID: {claim.ClaimId}");
                }
                catch (DbUpdateException dbEx)
                {
                    var innerException = dbEx.InnerException;
                    var errorMessage = innerException?.Message ?? dbEx.Message;

                    _logger?.LogError(dbEx, $"Database error saving claim: {errorMessage}");

                    if (errorMessage.Contains("UNIQUE") || errorMessage.Contains("duplicate"))
                    {
                        ModelState.AddModelError("", "A similar claim already exists.");
                    }
                    else if (errorMessage.Contains("String or binary data would be truncated"))
                    {
                        ModelState.AddModelError("", $"Database error: The claim reference is too long.");
                    }
                    else
                    {
                        ModelState.AddModelError("", $"Database error: {errorMessage}");
                    }

                    ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                    ViewBag.LecturerRate = user.HourlyRate;
                    ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                    return View(model);
                }

                TempData["SuccessMessage"] = $"Claim submitted successfully! Reference: {claim.ClaimReference}. Total Amount: R{claim.TotalAmount:F2}";
                return RedirectToAction("ViewClaims");
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, $"Unexpected error in SubmitClaim for user {userId}");
                ModelState.AddModelError("", $"An unexpected error occurred: {ex.Message}");

                try
                {
                    if (userId > 0)
                    {
                        var user = await _context.Users.FindAsync(userId);
                        if (user != null)
                        {
                            model.HourlyRate = user.HourlyRate;
                            ViewBag.LecturerName = $"{user.FirstName} {user.LastName}";
                            ViewBag.LecturerRate = user.HourlyRate;
                            ViewBag.MaxHoursPerMonth = MAX_HOURS_PER_MONTH;
                        }
                    }
                }
                catch { }

                return View(model);
            }
        }

        public async Task<IActionResult> ViewClaims()
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var claims = await _context.Claims
                    .Where(c => c.LecturerId == userId)
                    .Include(c => c.Documents)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .OrderByDescending(c => c.SubmissionDate)
                    .ToListAsync();

                return View(claims);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "ViewClaims error");
                TempData["ErrorMessage"] = "Error loading claims. Please try again.";
                return View(new List<Claim>());
            }
        }

        public IActionResult UploadDocuments(int claimId)
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var claim = _context.Claims.FirstOrDefault(c => c.ClaimId == claimId && c.LecturerId == userId);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found or access denied.";
                    return RedirectToAction("ViewClaims");
                }

                ViewBag.ClaimId = claimId;
                ViewBag.ClaimReference = claim.ClaimReference;
                return View();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "UploadDocuments GET error");
                TempData["ErrorMessage"] = "Error loading upload page.";
                return RedirectToAction("ViewClaims");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UploadDocuments(int claimId, IFormFile file, string description)
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                if (file == null || file.Length == 0)
                {
                    TempData["ErrorMessage"] = "Please select a file to upload.";
                    return RedirectToAction("UploadDocuments", new { claimId });
                }

                var allowedExtensions = new[] { ".pdf", ".docx", ".xlsx", ".jpg", ".jpeg", ".png" };
                var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

                if (!allowedExtensions.Contains(extension))
                {
                    TempData["ErrorMessage"] = "Only PDF, DOCX, XLSX, JPG, JPEG, and PNG files are allowed.";
                    return RedirectToAction("UploadDocuments", new { claimId });
                }

                if (file.Length > 10 * 1024 * 1024)
                {
                    TempData["ErrorMessage"] = "File size cannot exceed 10MB.";
                    return RedirectToAction("UploadDocuments", new { claimId });
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var claim = await _context.Claims
                    .FirstOrDefaultAsync(c => c.ClaimId == claimId && c.LecturerId == userId);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found or access denied.";
                    return RedirectToAction("ViewClaims");
                }

                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
                if (!Directory.Exists(uploadsFolder))
                    Directory.CreateDirectory(uploadsFolder);

                var fileName = $"{Guid.NewGuid()}{extension}";
                var filePath = Path.Combine(uploadsFolder, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                var document = new Document
                {
                    ClaimId = claimId,
                    FileName = file.FileName,
                    FilePath = fileName,
                    FileType = extension,
                    FileSize = file.Length,
                    Description = description,
                    ContentType = file.ContentType,
                    UploadDate = DateTime.Now,
                    IsVerified = false
                };

                _context.Documents.Add(document);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Document uploaded successfully!";
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "UploadDocuments POST error");
                TempData["ErrorMessage"] = $"An error occurred while uploading: {ex.Message}";
            }

            return RedirectToAction("ViewClaims");
        }

        public async Task<IActionResult> GetClaimDetails(int id)
        {
            try
            {
                if (!ValidateSession())
                {
                    return Content("<div class='alert alert-danger'>Session expired. Please login again.</div>");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var claim = await _context.Claims
                    .Include(c => c.Lecturer)
                    .Include(c => c.Documents)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .FirstOrDefaultAsync(c => c.ClaimId == id && c.LecturerId == userId);

                if (claim == null)
                {
                    return Content("<div class='alert alert-danger'>Claim not found.</div>");
                }

                return PartialView("_ClaimDetailsPartial", claim);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "GetClaimDetails error");
                return Content($"<div class='alert alert-danger'>Error loading claim details: {ex.Message}</div>");
            }
        }

        public async Task<IActionResult> DownloadDocument(int documentId)
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var document = await _context.Documents
                    .Include(d => d.Claim)
                    .FirstOrDefaultAsync(d => d.DocumentId == documentId);

                if (document == null || document.Claim.LecturerId != userId)
                {
                    TempData["ErrorMessage"] = "Document not found or access denied.";
                    return RedirectToAction("ViewClaims");
                }

                var path = Path.Combine(_environment.WebRootPath, "uploads", document.FilePath);
                if (!System.IO.File.Exists(path))
                {
                    TempData["ErrorMessage"] = "File not found on server.";
                    return RedirectToAction("ViewClaims");
                }

                var memory = new MemoryStream();
                using (var stream = new FileStream(path, FileMode.Open))
                {
                    await stream.CopyToAsync(memory);
                }
                memory.Position = 0;

                return File(memory, document.ContentType, document.FileName);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "DownloadDocument error");
                TempData["ErrorMessage"] = "Error downloading document.";
                return RedirectToAction("ViewClaims");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteDocument(int documentId)
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier).Value);
                var document = await _context.Documents
                    .Include(d => d.Claim)
                    .FirstOrDefaultAsync(d => d.DocumentId == documentId && d.Claim.LecturerId == userId);

                if (document == null)
                {
                    TempData["ErrorMessage"] = "Document not found or access denied.";
                    return RedirectToAction("ViewClaims");
                }

                var filePath = Path.Combine(_environment.WebRootPath, "uploads", document.FilePath);
                if (System.IO.File.Exists(filePath))
                {
                    System.IO.File.Delete(filePath);
                }

                _context.Documents.Remove(document);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Document deleted successfully!";
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "DeleteDocument error");
                TempData["ErrorMessage"] = $"An error occurred: {ex.Message}";
            }

            return RedirectToAction("ViewClaims");
        }

        // PART 3: Helper method for session validation
        private bool ValidateSession()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var userRole = HttpContext.Session.GetString("UserRole");
            return !string.IsNullOrEmpty(userId) && userRole == "LECTURER";
        }
    }
}