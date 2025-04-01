using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class QuizController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
