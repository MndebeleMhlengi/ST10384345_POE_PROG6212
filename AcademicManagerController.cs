using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using CMCS.Data;
using CMCS.Models;
using System.Security.Claims;
using Claim = CMCS.Models.Claim;

namespace CMCS.Controllers
{
    [Authorize(Roles = "ACADEMIC_MANAGER")]
    public class AcademicManagerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AcademicManagerController> _logger;

        public AcademicManagerController(ApplicationDbContext context, ILogger<AcademicManagerController> logger)
        {
            _context = context;
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

                var pendingClaims = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.APPROVED_PC && c.IsActive)
                    .Include(c => c.Lecturer)
                    .Include(c => c.Documents)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .OrderBy(c => c.LastModifiedDate)
                    .ToListAsync();

                var finalApprovedClaims = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.APPROVED_FINAL && c.IsActive)
                    .Include(c => c.Lecturer)
                    .ToListAsync();

                var rejectedClaims = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.REJECTED && c.IsActive)
                    .Include(c => c.Lecturer)
                    .ToListAsync();

                ViewBag.TotalPending = pendingClaims.Count;
                ViewBag.TotalFinalApproved = finalApprovedClaims.Count;
                ViewBag.TotalRejected = rejectedClaims.Count;
                ViewBag.TotalProcessed = finalApprovedClaims.Count + rejectedClaims.Count;
                ViewBag.TotalAmountPending = pendingClaims.Sum(c => c.TotalAmount);
                ViewBag.TotalAmountApproved = finalApprovedClaims.Sum(c => c.TotalAmount);

                return View(pendingClaims);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading Academic Manager dashboard");
                TempData["ErrorMessage"] = "Error loading dashboard. Please try again.";
                return View(new List<Claim>());
            }
        }

        public async Task<IActionResult> ReviewClaim(int id)
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var claim = await _context.Claims
                    .Include(c => c.Lecturer)
                    .Include(c => c.Documents)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .FirstOrDefaultAsync(c => c.ClaimId == id && c.IsActive);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found.";
                    return RedirectToAction("Dashboard");
                }

                if (claim.Status != ClaimStatus.APPROVED_PC)
                {
                    TempData["ErrorMessage"] = $"This claim is not pending Academic Manager approval. Current status: {claim.Status}";
                    return RedirectToAction("Dashboard");
                }

                if (claim.TotalAmount == 0)
                {
                    claim.TotalAmount = claim.HoursWorked * claim.HourlyRate;
                }

                return View(claim);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading claim {ClaimId} for review", id);
                TempData["ErrorMessage"] = "Error loading claim details.";
                return RedirectToAction("Dashboard");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> FinalApprove(int claimId, string comments)
        {
            try
            {
                if (!ValidateSession())
                {
                    TempData["ErrorMessage"] = "Session expired. Please log in again.";
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
                var user = await _context.Users.FindAsync(userId);

                var claim = await _context.Claims
                    .Include(c => c.Lecturer)
                    .Include(c => c.Approvals)
                    .FirstOrDefaultAsync(c => c.ClaimId == claimId && c.IsActive);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found.";
                    return RedirectToAction("Dashboard");
                }

                if (claim.Status != ClaimStatus.APPROVED_PC)
                {
                    TempData["ErrorMessage"] = $"This claim is not pending Academic Manager approval. Current status: {claim.Status}";
                    return RedirectToAction("ReviewClaim", new { id = claimId });
                }

                await using var transaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    claim.Status = ClaimStatus.APPROVED_FINAL;
                    claim.LastModifiedDate = DateTime.Now;

                    if (claim.TotalAmount == 0)
                    {
                        claim.TotalAmount = claim.HoursWorked * claim.HourlyRate;
                    }

                    var approval = new ClaimApproval
                    {
                        ClaimId = claimId,
                        ApproverId = userId,
                        Level = ApprovalLevel.ACADEMIC_MANAGER,
                        Status = ApprovalStatus.APPROVED,
                        Comments = string.IsNullOrWhiteSpace(comments) ?
                            "Claim approved by Academic Manager." :
                            comments.Trim(),
                        RejectionReason = string.Empty,
                        ReviewDate = DateTime.Now,
                        ApprovalDate = DateTime.Now,
                        IsActive = true
                    };

                    _context.ClaimApprovals.Add(approval);
                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync();

                    _logger.LogInformation("Claim {ClaimId} given final approval by Academic Manager {UserId}", claimId, userId);
                    TempData["SuccessMessage"] = $"Claim {claim.ClaimReference} given final approval! It is now ready for HR payment processing.";
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (DbUpdateException dbEx)
            {
                _logger.LogError(dbEx, "Database error while final approving claim {ClaimId}", claimId);
                TempData["ErrorMessage"] = "Database error while approving claim. Please try again.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while final approving claim {ClaimId}", claimId);
                TempData["ErrorMessage"] = "Error approving claim. Please try again.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }

            return RedirectToAction("Dashboard");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RejectClaim(int claimId, string reason)
        {
            try
            {
                if (!ValidateSession())
                {
                    TempData["ErrorMessage"] = "Session expired. Please log in again.";
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
                var user = await _context.Users.FindAsync(userId);

                if (string.IsNullOrWhiteSpace(reason))
                {
                    TempData["ErrorMessage"] = "Please provide a reason for rejection.";
                    return RedirectToAction("ReviewClaim", new { id = claimId });
                }

                var claim = await _context.Claims
                    .Include(c => c.Lecturer)
                    .FirstOrDefaultAsync(c => c.ClaimId == claimId && c.IsActive);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found.";
                    return RedirectToAction("Dashboard");
                }

                if (claim.Status != ClaimStatus.APPROVED_PC)
                {
                    TempData["ErrorMessage"] = $"This claim is not pending Academic Manager approval. Current status: {claim.Status}";
                    return RedirectToAction("ReviewClaim", new { id = claimId });
                }

                await using var transaction = await _context.Database.BeginTransactionAsync();

                try
                {
                    claim.Status = ClaimStatus.REJECTED;
                    claim.LastModifiedDate = DateTime.Now;

                    var approval = new ClaimApproval
                    {
                        ClaimId = claimId,
                        ApproverId = userId,
                        Level = ApprovalLevel.ACADEMIC_MANAGER,
                        Status = ApprovalStatus.REJECTED,
                        Comments = string.Empty,
                        RejectionReason = reason.Trim(),
                        ReviewDate = DateTime.Now,
                        ApprovalDate = DateTime.Now,
                        IsActive = true
                    };

                    _context.ClaimApprovals.Add(approval);
                    await _context.SaveChangesAsync();
                    await transaction.CommitAsync();

                    _logger.LogInformation("Claim {ClaimId} rejected by Academic Manager {UserId}", claimId, userId);
                    TempData["SuccessMessage"] = $"Claim {claim.ClaimReference} rejected successfully. The lecturer has been notified.";
                }
                catch (Exception ex)
                {
                    await transaction.RollbackAsync();
                    throw;
                }
            }
            catch (DbUpdateException dbEx)
            {
                _logger.LogError(dbEx, "Database error while rejecting claim {ClaimId}", claimId);
                TempData["ErrorMessage"] = "Database error while rejecting claim. Please try again.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while rejecting claim {ClaimId}", claimId);
                TempData["ErrorMessage"] = "Error rejecting claim. Please try again.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }

            return RedirectToAction("Dashboard");
        }

        public async Task<IActionResult> ApprovedClaims()
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var approvedClaims = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.APPROVED_FINAL && c.IsActive)
                    .Include(c => c.Lecturer)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .Include(c => c.Documents)
                    .OrderByDescending(c => c.LastModifiedDate)
                    .ToListAsync();

                ViewBag.TotalAmount = approvedClaims.Sum(c => c.TotalAmount);

                return View(approvedClaims);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading approved claims");
                TempData["ErrorMessage"] = "Error loading approved claims.";
                return View(new List<Claim>());
            }
        }

        public async Task<IActionResult> RejectedClaims()
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var rejectedClaims = await _context.Claims
                    .Where(c => c.Status == ClaimStatus.REJECTED && c.IsActive)
                    .Include(c => c.Lecturer)
                    .Include(c => c.Approvals)
                        .ThenInclude(a => a.Approver)
                    .Include(c => c.Documents)
                    .OrderByDescending(c => c.LastModifiedDate)
                    .ToListAsync();

                return View(rejectedClaims);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading rejected claims");
                TempData["ErrorMessage"] = "Error loading rejected claims.";
                return View(new List<Claim>());
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

                var document = await _context.Documents
                    .Include(d => d.Claim)
                    .FirstOrDefaultAsync(d => d.DocumentId == documentId);

                if (document == null)
                {
                    TempData["ErrorMessage"] = "Document not found.";
                    return RedirectToAction("Dashboard");
                }

                var claim = document.Claim;
                if (claim == null || !claim.IsActive)
                {
                    TempData["ErrorMessage"] = "Claim not found or inaccessible.";
                    return RedirectToAction("Dashboard");
                }

                var path = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads", document.FilePath);
                if (!System.IO.File.Exists(path))
                {
                    TempData["ErrorMessage"] = "File not found on server.";
                    return RedirectToAction("ReviewClaim", new { id = document.ClaimId });
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
                _logger.LogError(ex, "Error downloading document {DocumentId}", documentId);
                TempData["ErrorMessage"] = "Error downloading document.";
                return RedirectToAction("Dashboard");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RequestClarification(int claimId, string clarificationRequest)
        {
            try
            {
                if (!ValidateSession())
                {
                    TempData["ErrorMessage"] = "Session expired. Please log in again.";
                    return RedirectToAction("Login", "Account");
                }

                var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");

                if (string.IsNullOrWhiteSpace(clarificationRequest))
                {
                    TempData["ErrorMessage"] = "Please provide clarification details.";
                    return RedirectToAction("ReviewClaim", new { id = claimId });
                }

                var claim = await _context.Claims
                    .Include(c => c.Lecturer)
                    .FirstOrDefaultAsync(c => c.ClaimId == claimId && c.IsActive);

                if (claim == null)
                {
                    TempData["ErrorMessage"] = "Claim not found.";
                    return RedirectToAction("Dashboard");
                }

                var approval = new ClaimApproval
                {
                    ClaimId = claimId,
                    ApproverId = userId,
                    Level = ApprovalLevel.ACADEMIC_MANAGER,
                    Status = ApprovalStatus.PENDING_CLARIFICATION,
                    Comments = $"Clarification requested: {clarificationRequest.Trim()}",
                    ReviewDate = DateTime.Now,
                    IsActive = true
                };

                _context.ClaimApprovals.Add(approval);
                await _context.SaveChangesAsync();

                TempData["SuccessMessage"] = "Clarification requested successfully. The Programme Coordinator has been notified.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error requesting clarification for claim {ClaimId}", claimId);
                TempData["ErrorMessage"] = "Error requesting clarification. Please try again.";
                return RedirectToAction("ReviewClaim", new { id = claimId });
            }
        }

        public async Task<IActionResult> Reports()
        {
            try
            {
                if (!ValidateSession())
                {
                    return RedirectToAction("Login", "Account");
                }

                var startDate = DateTime.Now.AddMonths(-3);

                var claims = await _context.Claims
                    .Where(c => c.SubmissionDate >= startDate && c.IsActive)
                    .Include(c => c.Lecturer)
                    .Include(c => c.Approvals)
                    .ToListAsync();

                var monthlyStats = claims
                    .GroupBy(c => new { c.YearWorked, c.MonthWorked })
                    .Select(g => new
                    {
                        Period = new DateTime(g.Key.YearWorked, g.Key.MonthWorked, 1),
                        TotalClaims = g.Count(),
                        ApprovedClaims = g.Count(c => c.Status == ClaimStatus.APPROVED_FINAL || c.Status == ClaimStatus.PAID),
                        RejectedClaims = g.Count(c => c.Status == ClaimStatus.REJECTED),
                        TotalAmount = g.Where(c => c.Status == ClaimStatus.APPROVED_FINAL || c.Status == ClaimStatus.PAID).Sum(c => c.TotalAmount)
                    })
                    .OrderBy(x => x.Period)
                    .ToList();

                ViewBag.MonthlyStats = monthlyStats;
                ViewBag.TotalClaims = claims.Count;
                ViewBag.ApprovedClaims = claims.Count(c => c.Status == ClaimStatus.APPROVED_FINAL || c.Status == ClaimStatus.PAID);
                ViewBag.RejectedClaims = claims.Count(c => c.Status == ClaimStatus.REJECTED);
                ViewBag.TotalAmount = claims.Where(c => c.Status == ClaimStatus.APPROVED_FINAL || c.Status == ClaimStatus.PAID).Sum(c => c.TotalAmount);

                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading reports");
                TempData["ErrorMessage"] = "Error loading reports.";
                return View();
            }
        }

        // PART 3: Helper method for session validation
        private bool ValidateSession()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var userRole = HttpContext.Session.GetString("UserRole");
            return !string.IsNullOrEmpty(userId) && userRole == "ACADEMIC_MANAGER";
        }
    }
}