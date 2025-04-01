using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class RandomJokeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
