using CLIENT.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CLIENT.Controllers
{
    public class DashboardController : Controller
    {
        public IActionResult Index()
        {
            var userName = User.Identity?.Name;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            ViewBag.UserName = userName;
            ViewBag.Role = role;

            return View();
        }
    }
}
