// Controllers/HomeController.cs
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

public class HomeController : Controller
{
    public IActionResult Index()
    {
        // Redirect to appropriate dashboard based on user role
        if (User.IsInRole("Lecturer"))
        {
            return RedirectToAction("Dashboard", "Lecturer");
        }
        else if (User.IsInRole("HR"))
        {
            return RedirectToAction("Dashboard", "HR");
        }
        else if (User.IsInRole("ProgrammeCoordinator"))
        {
            return RedirectToAction("Dashboard", "ProgrammeCoordinator");
        }
        else if (User.IsInRole("AcademicManager"))
        {
            return RedirectToAction("Dashboard", "AcademicManager");
        }

        // For logged-out users or unknown roles, show a general home page
        return View();
    }

    public IActionResult Privacy()
    {
        return View();
    }
}