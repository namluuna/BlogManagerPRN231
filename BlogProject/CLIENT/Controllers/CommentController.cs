using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class CommentController : Controller
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
