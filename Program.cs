using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.Cookies;
using CMCS.Data;

namespace CMCS
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container
            builder.Services.AddControllersWithViews();

            // Add Entity Framework
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

            // PART 3: Add Session support
            builder.Services.AddDistributedMemoryCache(); // Required for session
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30); // Session timeout
                options.Cookie.HttpOnly = true; // Security: Cookie only accessible via HTTP
                options.Cookie.IsEssential = true; // Required for GDPR compliance
                options.Cookie.Name = ".CMCS.Session"; // Custom session cookie name
            });

            // Add Authentication
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Account/Login";
                    options.LogoutPath = "/Account/Logout";
                    options.AccessDeniedPath = "/Account/AccessDenied";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                    options.SlidingExpiration = true;
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // HTTPS only in production
                });

            // Add Authorization
            builder.Services.AddAuthorization(options =>
            {
                // PART 3: Define authorization policies for role-based access
                options.AddPolicy("LecturerOnly", policy => policy.RequireRole("LECTURER"));
                options.AddPolicy("CoordinatorOnly", policy => policy.RequireRole("PROGRAMME_COORDINATOR"));
                options.AddPolicy("ManagerOnly", policy => policy.RequireRole("ACADEMIC_MANAGER"));
                options.AddPolicy("HROnly", policy => policy.RequireRole("HR"));
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("ADMIN"));

                // Combined policies for multiple roles
                options.AddPolicy("ApproverAccess", policy =>
                    policy.RequireRole("PROGRAMME_COORDINATOR", "ACADEMIC_MANAGER", "HR"));
            });

            var app = builder.Build();

            // Configure the HTTP request pipeline
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }
            else
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();

            // PART 3: CRITICAL - Add session middleware BEFORE authentication
            app.UseSession();

            app.UseAuthentication();
            app.UseAuthorization();

            // PART 3: Add custom middleware to prevent unauthorized page access
            app.Use(async (context, next) =>
            {
                var path = context.Request.Path.Value?.ToLower();
                var isAuthenticated = context.User?.Identity?.IsAuthenticated ?? false;

                // Allow access to login, logout, and public pages
                if (path == "/" || path == "/account/login" || path == "/account/logout" ||
                    path == "/home/index" || path == "/home/privacy")
                {
                    await next();
                    return;
                }

                // Redirect to login if not authenticated
                if (!isAuthenticated && !path.StartsWith("/account"))
                {
                    context.Response.Redirect("/Account/Login");
                    return;
                }

                await next();
            });

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}