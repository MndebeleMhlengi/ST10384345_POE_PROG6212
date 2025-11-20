# Contract Monthly Claim System (CMCS)
## POE Part 3 - Complete Documentation

Student Name: Mhlengi Mndebele  
Student Number: 
Module: PROG6212 - Programming 2B  
Submission Date: 21 November 2025

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Changes from Part 2 to Part 3](#changes-from-part-2-to-part-3)
3. [System Requirements](#system-requirements)
4. [Installation Guide](#installation-guide)
5. [Key Features - Part 3](#key-features-part-3)
6. [User Guides](#user-guides)
7. [Database Schema](#database-schema)
8. [Testing](#testing)
9. [Security Features](#security-features)
10. [Troubleshooting](#troubleshooting)
11. [Version Control](#version-control)
12. [Future Enhancements](#future-enhancements)

---

## Project Overview

The Contract Monthly Claim System (CMCS) is a comprehensive web application built with ASP.NET Core MVC that streamlines the process of submitting, reviewing, and approving monthly claims for Independent Contractor lecturers.

### Purpose
- Enable lecturers to submit monthly work claims with supporting documentation
- Provide a multi-level approval workflow (Programme Coordinator → Academic Manager → HR)
- Allow HR to manage users and process payments
- Generate reports and track claim status throughout the approval process

### Technology Stack
- **Backend:** ASP.NET Core MVC (.NET 8.0)
- **Database:** SQL Server 2019+
- **ORM:** Entity Framework Core
- **Frontend:** Razor Views, Bootstrap 5, jQuery
- **Authentication:** Cookie-based with HMACSHA512 hashing
- **Session Management:** ASP.NET Core Session with 30-minute timeout

---

## Changes from Part 2 to Part 3

### Based on Lecturer Feedback

All changes in Part 3 were implemented based on specific feedback from the lecturer to improve security, automation, and user experience.

#### 1. ✅ HR as Super User

**What Changed:**
- **Part 2:** Users could self-register with any role
- **Part 3:** Public registration completely disabled - only HR can create accounts

**Why:**
- Centralized user management
- Better security control
- Prevents unauthorized role assignment
- Ensures all lecturers have proper hourly rates set

**Implementation:**
```csharp
// AccountController.cs - Register now redirects to login
public IActionResult Register()
{
    TempData["InfoMessage"] = "User registration is handled by HR administrators.";
    return RedirectToAction("Login");
}

// HRController.cs - CreateUser action
[HttpPost]
public async Task<IActionResult> CreateUser(RegisterViewModel model)
{
    var user = new User
    {
        FirstName = model.FirstName,
        LastName = model.LastName,
        Email = model.Email,
        Password = HashPassword(model.Password),
        Role = model.Role,
        HourlyRate = model.HourlyRate ?? 0,
        // ... other properties
    };
    _context.Users.Add(user);
    await _context.SaveChangesAsync();
}
```

**Files Changed:**
- `AccountController.cs` - Disabled Register GET/POST
- `HRController.cs` - Added CreateUser, EditUser, DeleteUser actions
- `Views/HR/CreateUser.cshtml` - New view for user creation
- `Views/HR/ManageUsers.cshtml` - New view for user management

#### 2. ✅ Auto-Pull Hourly Rate

**What Changed:**
- **Part 2:** Lecturers manually entered their hourly rate when submitting claims
- **Part 3:** Hourly rate automatically pulled from user profile (managed by HR)

**Why:**
- Eliminates manual entry errors
- Ensures consistency across all claims
- HR maintains full control over rates
- Prevents lecturers from inflating rates

**Implementation:**
```csharp
// LecturerController.cs - SubmitClaim GET
public async Task<IActionResult> SubmitClaim()
{
    var user = await _context.Users.FindAsync(userId);
    
    // Auto-pull hourly rate from profile
    var model = new ClaimSubmissionViewModel
    {
        HourlyRate = user.HourlyRate, // From HR-managed profile
        YearWorked = DateTime.Now.Year,
        MonthWorked = DateTime.Now.Month
    };
    
    ViewBag.LecturerRate = user.HourlyRate;
    return View(model);
}

// POST - Force rate from profile
model.HourlyRate = user.HourlyRate; // Cannot be changed
ModelState.Remove("HourlyRate");
```

**Files Changed:**
- `LecturerController.cs` - Modified SubmitClaim GET/POST
- `Views/Lecturer/SubmitClaim.cshtml` - Updated to show rate from profile
- Display shows: "Hourly Rate: R 250.00 (Set by HR)"

#### 3. ✅ Auto-Calculation

**What Changed:**
- **Part 2:** Total amount calculated after submission
- **Part 3:** Total amount calculated in real-time as hours are entered

**Why:**
- Immediate feedback for lecturers
- Better user experience
- Reduces submission errors
- Transparent calculation process

**Implementation:**
```javascript
// SubmitClaim.cshtml - JavaScript
function calculateTotal() {
    const hours = parseFloat(hoursInput.value) || 0;
    const total = hours * hourlyRate;
    displayHours.textContent = hours.toFixed(1);
    calculatedTotal.textContent = 'R ' + total.toFixed(2);
}
hoursInput.addEventListener('input', calculateTotal);
```

```csharp
// Server-side auto-calculation
claim.TotalAmount = claim.HoursWorked * claim.HourlyRate;
```

**Files Changed:**
- `Views/Lecturer/SubmitClaim.cshtml` - Added JavaScript calculation
- `LecturerController.cs` - Server-side calculation confirmation

#### 4. ✅ 180-Hour Maximum Validation

**What Changed:**
- **Part 2:** No maximum limit on hours per month
- **Part 3:** Maximum 180 hours per month enforced

**Why:**
- Realistic work hour limits
- Prevents data entry errors
- Compliance with labor regulations
- Catches accidental typos

**Implementation:**
```csharp
// LecturerController.cs
private const decimal MAX_HOURS_PER_MONTH = 180m;

if (model.HoursWorked > MAX_HOURS_PER_MONTH)
{
    ModelState.AddModelError("HoursWorked", 
        $"Hours cannot exceed {MAX_HOURS_PER_MONTH} per month. " +
        $"You entered {model.HoursWorked} hours.");
    return View(model);
}
```

```javascript
// Client-side validation
if (hours > maxHours) {
    hoursInput.classList.add('is-invalid');
    showWarning('Hours exceed maximum of 180 hours per month!');
}
```

**Files Changed:**
- `LecturerController.cs` - Added MAX_HOURS_PER_MONTH constant
- `Views/Lecturer/SubmitClaim.cshtml` - Client-side validation

#### 5. ✅ Session Management

**What Changed:**
- **Part 2:** Basic cookie authentication
- **Part 3:** Full session management with 30-minute timeout

**Why:**
- Enhanced security
- Automatic logout after inactivity
- Better user state management
- Prevents unauthorized access

**Implementation:**
```csharp
// Program.cs - Session configuration
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.Name = ".CMCS.Session";
});

app.UseSession(); // Before UseAuthentication()
app.UseAuthentication();

// AccountController.cs - Store session data on login
HttpContext.Session.SetString("UserId", user.UserId.ToString());
HttpContext.Session.SetString("UserRole", user.Role.ToString());

// Clear session on logout
HttpContext.Session.Clear();
```

**Files Changed:**
- `Program.cs` - Added session configuration
- `AccountController.cs` - Session storage/clearing
- All Controllers - Added ValidateSession() helper method

#### 6. ✅ Enhanced Access Control

**What Changed:**
- **Part 2:** Basic role authorization
- **Part 3:** Multi-layered access control with policies

**Why:**
- Stronger security
- Prevents role escalation
- Clear authorization rules
- Better error handling

**Implementation:**
```csharp
// Program.cs - Authorization policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("LecturerOnly", 
        policy => policy.RequireRole("LECTURER"));
    options.AddPolicy("HROnly", 
        policy => policy.RequireRole("HR"));
    // ... other policies
});

// Session validation in each controller
private bool ValidateSession()
{
    var userId = HttpContext.Session.GetString("UserId");
    var userRole = HttpContext.Session.GetString("UserRole");
    return !string.IsNullOrEmpty(userId) && userRole == "HR";
}
```

**Files Changed:**
- `Program.cs` - Authorization policies
- All Controllers - ValidateSession() method
- Views - Conditional rendering based on role

#### 7. ✅ Reports & Invoice Generation

**What Changed:**
- **Part 2:** Basic payment reports
- **Part 3:** LINQ-based invoice generation with CSV export

**Why:**
- Advanced reporting capabilities
- Data export for accounting
- Better financial tracking
- Professional invoice generation

**Implementation:**
```csharp
// HRController.cs - Payment reports with LINQ
public async Task<IActionResult> PaymentReports(string period = "current-month")
{
    var paidClaims = await _context.Claims
        .Where(c => c.Status == ClaimStatus.PAID && c.IsActive)
        .Include(c => c.Lecturer)
        .OrderByDescending(c => c.LastModifiedDate)
        .ToListAsync();
    
    // Filter by period using LINQ
    if (period == "current-month")
    {
        paidClaims = paidClaims
            .Where(c => c.LastModifiedDate.Month == now.Month &&
                       c.LastModifiedDate.Year == now.Year)
            .ToList();
    }
    
    ViewBag.TotalPaidAmount = paidClaims.Sum(c => c.TotalAmount);
    return View(paidClaims);
}

// CSV Export
public async Task<IActionResult> ExportPayments(string period)
{
    // Generate CSV content
    var csv = "Claim Reference,Lecturer,Hours,Amount,Paid Date\n";
    foreach (var c in paidClaims)
    {
        csv += $"\"{c.ClaimReference}\",\"{c.Lecturer.FirstName}\",...\n";
    }
    return File(Encoding.UTF8.GetBytes(csv), "text/csv", fileName);
}
```

**Files Changed:**
- `HRController.cs` - Enhanced PaymentReports and ExportPayments
- `Views/HR/PaymentReports.cshtml` - Period filter buttons

#### 8. ✅ User Deletion Feature

**What Changed:**
- **Part 2:** No way to delete users
- **Part 3:** HR can delete users with validation

**Why:**
- Complete user lifecycle management
- Remove test accounts
- Maintain database cleanliness
- Proper validation to prevent data loss

**Implementation:**
```csharp
// HRController.cs - DeleteUser
[HttpPost]
public async Task<IActionResult> DeleteUser(int id)
{
    var user = await _context.Users
        .Include(u => u.Claims)
        .FirstOrDefaultAsync(u => u.UserId == id);
    
    // Cannot delete self
    if (currentUserId == id)
    {
        TempData["ErrorMessage"] = "Cannot delete your own HR account.";
        return RedirectToAction(nameof(ManageUsers));
    }
    
    // Cannot delete lecturer with claims
    if (user.Role == UserRole.LECTURER && user.Claims.Any())
    {
        TempData["ErrorMessage"] = "Cannot delete lecturer with submitted claims.";
        return RedirectToAction(nameof(ManageUsers));
    }
    
    _context.Users.Remove(user);
    await _context.SaveChangesAsync();
}
```

**Files Changed:**
- `HRController.cs` - Added DeleteUser action
- `Views/HR/ManageUsers.cshtml` - Added delete button

---

## System Requirements

### Hardware Requirements
- **Processor:** Intel Core i3 or equivalent
- **RAM:** 4GB minimum, 8GB recommended
- **Storage:** 500MB free space
- **Network:** Internet connection for development tools

### Software Requirements
- **Operating System:** Windows 10/11, macOS, or Linux
- **.NET SDK:** .NET 8.0 or later
- **Database:** SQL Server 2019 or later (Express Edition acceptable)
- **IDE:** Visual Studio 2022 or VS Code (with C# extension)
- **Web Browser:** Chrome, Firefox, or Edge (latest versions)

### Development Tools
- Git for version control
- SQL Server Management Studio (SSMS) - optional
- Postman for API testing - optional

---

## Installation Guide

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/CMCS.git
cd CMCS
```

### Step 2: Database Setup

1. **Update Connection String**

Edit `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=YOUR_SERVER_NAME;Database=CMCSDb;Trusted_Connection=true;TrustServerCertificate=True;"
  }
}
```

Replace `YOUR_SERVER_NAME` with your SQL Server instance name (e.g., `localhost\SQLEXPRESS`)

2. **Create Database**

Using Package Manager Console in Visual Studio:
```powershell
Update-Database
```

OR using .NET CLI:
```bash
dotnet ef database update
```

3. **Create Initial HR User**

Run this SQL script in SSMS:
```sql
USE CMCSDb;

INSERT INTO Users (FirstName, LastName, Email, Password, Role, HourlyRate, IsActive, CreatedDate, LastModifiedDate)
VALUES (
    'HR', 
    'Administrator', 
    'hr@cmcs.com', 
    'HASHED_PASSWORD_HERE', -- Use actual hashed password
    4, -- HR role
    0, -- HR doesn't need hourly rate
    1, -- IsActive
    GETDATE(),
    GETDATE()
);
```

**Note:** For the password, you'll need to hash it first. You can create a temporary method in AccountController to hash a password, or use the registration form once to get a hashed password.

### Step 3: Run Application

```bash
dotnet run
```

OR press F5 in Visual Studio.

### Step 4: Access Application

Open your browser and navigate to:
```
https://localhost:5001
```

### Step 5: First Login

```
Email: hr@cmcs.com
Password: [password you set]
```

---

## Key Features - Part 3

### 1. HR User Management

**Overview:** HR administrators have complete control over user creation and management.

**Features:**
- Create users for all roles (Lecturer, Coordinator, Manager, HR)
- Set hourly rates for lecturers
- Edit user information
- Activate/Deactivate users
- Delete users (with validation)
- View lecturer details and claim history

**How to Use:**
1. Log in as HR
2. Navigate to "Manage Users"
3. Click "Create User"
4. Fill in all required information:
   - First Name, Last Name
   - Email (used for login)
   - Password
   - Role selection
   - For Lecturers: Set Hourly Rate
   - Phone, Department, Employee Number (optional)
5. Click "Create User"
6. Provide login credentials to the new user

**Screenshots:**
- CreateUser form with dynamic fields
- ManageUsers dashboard with all users
- Edit user interface
- Delete confirmation

### 2. Automated Lecturer Claim Submission

**Overview:** Lecturers submit claims with auto-pulled hourly rate and real-time calculation.

**Features:**
- Hourly rate automatically loaded from profile
- Real-time total amount calculation
- 180-hour maximum validation
- Cannot manually change hourly rate
- Visual calculation display

**How to Use:**
1. Log in as Lecturer
2. Navigate to "Submit Claim"
3. See your information displayed:
   - Name
   - Hourly Rate (set by HR)
4. Fill in claim details:
   - Select Month and Year
   - Enter Module Taught
   - Enter Hours Worked (max 180)
5. Watch total calculate automatically
6. Add optional notes
7. Click "Submit Claim"
8. Upload supporting documents

**Validation Rules:**
- Hours: 0.1 to 500
- Maximum per month: 180 hours
- Month: 1-12
- Year: 2020-2030
- Module: Required, max 100 characters

### 3. Session Management

**Overview:** Secure session management with automatic timeout.

**Features:**
- 30-minute inactivity timeout
- HttpOnly cookies (no JavaScript access)
- Secure cookies (HTTPS only)
- Session data stored:
  - UserId
  - UserName
  - UserRole
  - UserEmail
- Automatic logout on timeout
- Session cleared on logout

**How It Works:**
1. User logs in → Session created
2. Session stored in memory with timeout
3. Every action validates session
4. After 30 minutes of inactivity → Session expires
5. User redirected to login page
6. Must log in again to continue

**Configuration:**
```csharp
// Program.cs
options.IdleTimeout = TimeSpan.FromMinutes(30);
```

**To change timeout:**
Edit Program.cs and adjust the minutes value.

### 4. Payment Reports & CSV Export

**Overview:** Generate payment reports with period filtering and CSV export.

**Features:**
- Filter by period:
  - Current Month
  - Last Month
  - All Time
- View summary statistics
- Detailed claim listing
- Export to CSV for Excel
- LINQ-based data aggregation

**How to Use:**
1. Log in as HR
2. Navigate to "Payment Reports"
3. Select period (Current Month/Last Month/All)
4. View report with:
   - Total paid amount
   - Number of paid claims
   - Detailed claim list
5. Click "Export CSV" to download
6. Open in Excel for further analysis

**CSV Format:**
```
Claim Reference,Lecturer,Month/Year,Hours,Amount,Paid Date
CLM-2411191234-ABC1,John Doe,Nov 2024,40,10000.00,2024-11-19
```

### 5. Multi-Level Approval Workflow

**Overview:** Claims go through a structured approval process.

**Workflow:**
```
Lecturer Submits → Programme Coordinator Approves → 
Academic Manager Final Approval → HR Marks as Paid → Complete
```

**Statuses:**
1. PENDING - Submitted by lecturer
2. UNDER_REVIEW - Being reviewed
3. APPROVED_PC - Approved by Programme Coordinator
4. APPROVED_FINAL - Final approval by Academic Manager
5. PAID - Marked as paid by HR
6. REJECTED - Rejected at any stage

**Features:**
- Track claim at every stage
- View approval history
- See approver comments
- Rejection reasons recorded
- Email notifications (future enhancement)

---

## User Guides

### HR Administrator Guide

#### Daily Tasks:
1. **Monitor Dashboard**
   - Check claims ready for payment
   - View statistics

2. **Create New Users**
   - Navigate to Manage Users → Create User
   - Set appropriate hourly rates for lecturers
   - Provide login credentials

3. **Process Payments**
   - Review approved claims
   - Mark individual claims as paid
   - OR select multiple and batch process

4. **Generate Reports**
   - Go to Payment Reports
   - Select period
   - Export CSV for accounting

5. **Manage User Information**
   - Update hourly rates as needed
   - Deactivate users who leave
   - Edit user details

#### Monthly Tasks:
- Generate monthly payment reports
- Review lecturer performance
- Update hourly rates if needed
- Archive old data

### Lecturer Guide

#### Submitting a Claim:
1. Log in to CMCS
2. Click "Submit Claim"
3. Verify your information:
   - Your name is displayed
   - Your hourly rate (set by HR) is shown
4. Fill in claim details:
   - Select the month you worked
   - Select the year
   - Enter the module you taught
   - Enter hours worked
5. Watch the total amount calculate automatically
6. Add any additional notes
7. Click "Submit Claim"
8. Upload supporting documents:
   - Timesheets
   - Attendance records
   - Assignment grading records

#### Tracking Your Claim:
1. Go to "View Claims"
2. Find your claim by reference number
3. Click on claim to see details:
   - Current status
   - Approval history
   - Comments from approvers
   - Documents attached

#### Understanding Statuses:
- **PENDING:** Waiting for Programme Coordinator review
- **APPROVED_PC:** Approved by Coordinator, awaiting Manager
- **APPROVED_FINAL:** Fully approved, awaiting payment
- **PAID:** Payment processed
- **REJECTED:** Not approved (see rejection reason)

### Programme Coordinator Guide

#### Reviewing Claims:
1. Log in to CMCS
2. View pending claims on dashboard
3. Click "Review" on a claim
4. Verify:
   - Hours worked are reasonable
   - Module is correct
   - Documents are attached and valid
5. Download documents to review
6. Decision:
   - **Approve:** Add comments (optional) → Click "Approve"
   - **Reject:** Add rejection reason → Click "Reject"

#### Best Practices:
- Review claims within 3 business days
- Always verify supporting documents
- Provide clear comments
- Contact lecturer if clarification needed

### Academic Manager Guide

#### Final Approval Process:
1. Log in to CMCS
2. View claims approved by Coordinators
3. Click "Review" on a claim
4. Verify:
   - Coordinator approval comments
   - Total amount is correct
   - All documentation present
5. Decision:
   - **Final Approve:** Claim goes to HR for payment
   - **Reject:** Provide detailed reason
   - **Request Clarification:** Ask Coordinator for more info

---

## Database Schema

### Tables Overview

#### Users Table
```sql
CREATE TABLE Users (
    UserId INT PRIMARY KEY IDENTITY(1,1),
    FirstName NVARCHAR(50) NOT NULL,
    LastName NVARCHAR(50) NOT NULL,
    Email NVARCHAR(100) UNIQUE NOT NULL,
    Password NVARCHAR(100) NOT NULL,
    Role INT NOT NULL, -- 0=Lecturer, 1=Coordinator, 2=Manager, 3=HR, 4=Admin
    PhoneNumber NVARCHAR(20),
    HourlyRate DECIMAL(18,2) DEFAULT 0, -- ⭐ Used for auto-calculation
    Department NVARCHAR(100),
    EmployeeNumber NVARCHAR(20),
    CreatedDate DATETIME DEFAULT GETDATE(),
    LastLoginDate DATETIME,
    LastModifiedDate DATETIME,
    IsActive BIT DEFAULT 1
);
```

#### Claims Table
```sql
CREATE TABLE Claims (
    ClaimId INT PRIMARY KEY IDENTITY(1,1),
    LecturerId INT NOT NULL FOREIGN KEY REFERENCES Users(UserId),
    MonthWorked INT NOT NULL CHECK (MonthWorked BETWEEN 1 AND 12),
    YearWorked INT NOT NULL CHECK (YearWorked BETWEEN 2020 AND 2030),
    HoursWorked DECIMAL(18,2) NOT NULL CHECK (HoursWorked > 0),
    HourlyRate DECIMAL(18,2) NOT NULL, -- ⭐ Copied from User.HourlyRate
    TotalAmount DECIMAL(18,2) NOT NULL, -- ⭐ HoursWorked * HourlyRate
    ModuleTaught NVARCHAR(100),
    AdditionalNotes NVARCHAR(500),
    Status INT DEFAULT 0, -- 0=Pending, 1=UnderReview, etc.
    ClaimReference NVARCHAR(20) UNIQUE,
    SubmissionDate DATETIME DEFAULT GETDATE(),
    LastModifiedDate DATETIME,
    IsActive BIT DEFAULT 1
);
```

#### ClaimApprovals Table
```sql
CREATE TABLE ClaimApprovals (
    ApprovalId INT PRIMARY KEY IDENTITY(1,1),
    ClaimId INT NOT NULL FOREIGN KEY REFERENCES Claims(ClaimId),
    ApproverId INT NOT NULL FOREIGN KEY REFERENCES Users(UserId),
    Level INT NOT NULL, -- 0=Coordinator, 1=Manager, 2=HR
    Status INT DEFAULT 0, -- 0=Pending, 1=Approved, 2=Rejected, 3=PendingClarification
    Comments NVARCHAR(500),
    RejectionReason NVARCHAR(200),
    ReviewDate DATETIME DEFAULT GETDATE(),
    ApprovalDate DATETIME,
    IsActive BIT DEFAULT 1
);
```

#### Documents Table
```sql
CREATE TABLE Documents (
    DocumentId INT PRIMARY KEY IDENTITY(1,1),
    ClaimId INT NOT NULL FOREIGN KEY REFERENCES Claims(ClaimId),
    FileName NVARCHAR(255) NOT NULL,
    FilePath NVARCHAR(500) NOT NULL,
    FileType NVARCHAR(10),
    FileSize BIGINT,
    ContentType NVARCHAR(100),
    Description NVARCHAR(200),
    UploadDate DATETIME DEFAULT GETDATE(),
    IsVerified BIT DEFAULT 0
);
```



## Testing

### Unit Tests Included

Located in `CMCSTests` project:

**ClaimCalculationTests.cs:**
- Test total amount calculation
- Test various hour and rate combinations
- Boundary value testing

**ClaimValidationTests.cs:**
- Test validation rules
- Test invalid inputs
- Test boundary conditions

**ClaimStatusTests.cs:**
- Test status workflow
- Test status transitions
- Test enum values

**UserRoleTests.cs:**
- Test role assignments
- Test role validation
- Test enum values

**DocumentTests.cs:**
- Test file upload validation
- Test file size limits
- Test allowed file types

### Running Tests

```bash
# Run all tests
dotnet test

# Run specific test class
dotnet test --filter ClassName=ClaimCalculationTests

# Run with detailed output
dotnet test --verbosity detailed
```

### Manual Testing Checklist

#### HR User Management:
- [ ] Create lecturer with hourly rate
- [ ] Create coordinator
- [ ] Create manager
- [ ] Update lecturer rate
- [ ] Edit user information
- [ ] Deactivate user
- [ ] Delete user (without claims)
- [ ] Try to delete self (should fail)
- [ ] Try to delete lecturer with claims (should fail)

#### Lecturer Claim Submission:
- [ ] Submit claim with valid data
- [ ] Verify hourly rate auto-pulled
- [ ] Verify total auto-calculated
- [ ] Try to submit with 181 hours (should fail)
- [ ] Try to submit with 180 hours (should succeed)
- [ ] Upload document
- [ ] View submitted claim
- [ ] Track claim status

#### Session Management:
- [ ] Log in and verify session created
- [ ] Navigate to different pages
- [ ] Wait 31 minutes (or adjust timeout to 1 min for testing)
- [ ] Try to access page (should redirect to login)
- [ ] Logout and verify session cleared

#### Reports:
- [ ] Generate current month report
- [ ] Generate last month report
- [ ] Export CSV
- [ ] Open CSV in Excel
- [ ] Verify data accuracy

---

## Security Features

### Authentication
- **Cookie-based authentication** with ASP.NET Core Identity cookies
- **HMACSHA512 password hashing** for secure storage
- **30-minute sliding expiration** for automatic logout
- **Anti-forgery tokens** on all POST requests

### Authorization
- **Role-based access control** with [Authorize] attributes
- **Authorization policies** for fine-grained control
- **Session validation** on every controller action
- **Cannot access pages** without proper role

### Data Protection
- **Parameterized queries** to prevent SQL injection
- **Input validation** on both client and server side
- **File upload validation** (type, size, extensions)
- **XSS protection** through Razor encoding

### Session Security
- **HttpOnly cookies** - JavaScript cannot access
- **Secure cookies** - HTTPS only in production
- **Session timeout** - 30 minutes of inactivity
- **Session data encryption** through ASP.NET Core

### Password Security
```csharp
private string HashPassword(string password)
{
    using var hmac = new HMACSHA512();
    return Convert.ToBase64String(
        hmac.ComputeHash(Encoding.UTF8.GetBytes(password))
    );
}
```

---

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed

**Error:** "A network-related or instance-specific error occurred..."

**Solution:**
1. Verify SQL Server is running
2. Check connection string in appsettings.json
3. Ensure server name is correct
4. Try using "localhost" or "(localdb)\MSSQLLocalDB"

#### 2. Session Timeout Too Frequent

**Problem:** Users getting logged out too quickly

**Solution:**
Edit `Program.cs`:
```csharp
options.IdleTimeout = TimeSpan.FromMinutes(60); // Increase to 60 minutes
```

#### 3. Hourly Rate Not Showing

**Problem:** Lecturer doesn't see hourly rate

**Solution:**
1. Verify HR set the hourly rate for that lecturer
2. Check Users table: `SELECT HourlyRate FROM Users WHERE UserId = X`
3. Ensure rate > 0
4. Try logging out and back in

#### 4. 180-Hour Validation Not Working

**Problem:** Can submit more than 180 hours

**Solution:**
1. Check JavaScript loaded: View page source, search for "calculateTotal"
2. Check MAX_HOURS_PER_MONTH constant in LecturerController
3. Clear browser cache and reload
4. Check browser console for errors

#### 5. Cannot Delete User

**Problem:** Error when trying to delete user

**Solution:**
1. Cannot delete self - this is by design
2. Cannot delete lecturer with claims - deactivate instead
3. Check if user has related records in database
4. Check logs for specific error

#### 6. CSV Export Not Downloading

**Problem:** CSV doesn't download when clicked

**Solution:**
1. Check browser's download folder
2. Check browser download settings
3. Verify there is data for the selected period
4. Check browser console for errors

#### 7. Auto-Calculation Not Working

**Problem:** Total amount not calculating

**Solution:**
1. Check hourly rate is set in user profile
2. Verify JavaScript loaded
3. Check browser console for errors
4. Try different browser
5. Clear cache and hard reload (Ctrl+F5)

