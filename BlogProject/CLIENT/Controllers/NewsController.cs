using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class NewsController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
