using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CLIENT.Models; // Import model

namespace CLIENT.Controllers
{
    
    public class BlogController : Controller
    {
        private readonly HttpClient _httpClient;

        public BlogController(HttpClient httpClient)
        {
            _httpClient = httpClient;
            _httpClient.BaseAddress = new Uri("https://localhost:57954/api/Posts");
        }

        public async Task<IActionResult> Index(string search = "", int page = 1, int pageSize = 10)
        {
            var response = await _httpClient.GetAsync($"?page={page}&pageSize={pageSize}");
            if (!response.IsSuccessStatusCode) return View(new List<BlogPostViewModel>());

            var json = await response.Content.ReadAsStringAsync();
            var posts = JsonConvert.DeserializeObject<List<BlogPostViewModel>>(json);
            return View(posts);
        }

        public IActionResult Create() => View();
        public IActionResult Edit(int id)
        {
            ViewBag.PostId = id;
            return View();
        }

        public IActionResult Delete(int id)
        {
            ViewBag.PostId = id; return View();
        }
    }
}
