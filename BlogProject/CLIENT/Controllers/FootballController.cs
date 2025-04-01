using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class FootballController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
