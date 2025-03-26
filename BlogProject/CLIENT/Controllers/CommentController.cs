using Microsoft.AspNetCore.Mvc;

namespace CLIENT.Controllers
{
    public class CommentController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
