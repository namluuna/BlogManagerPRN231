using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class WeatherController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
