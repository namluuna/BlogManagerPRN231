using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using CLIENT.Models;
using System.Text.Json;
using System.Net.Http.Headers; // Import model

namespace CLIENT.Controllers
{
    public class BlogsController : Controller
    {
        private readonly HttpClient _httpClient;
        string baseURL = "https://localhost:57954/";

        public BlogsController(HttpClient httpClient)
        {
            _httpClient = httpClient;        
        }

        //public async Task<IActionResult> Index(string search = "", int page = 1, int pageSize = 10)
        //{
        //    var response = await _httpClient.GetAsync($"?page={page}&pageSize={pageSize}");
        //    if (!response.IsSuccessStatusCode) return View(new List<BlogPostViewModel>());

        //    var json = await response.Content.ReadAsStringAsync();
        //    var posts = JsonConvert.DeserializeObject<List<BlogPostViewModel>>(json);
        //    return View(posts);
        //}

        public IActionResult Create() => View();

        

        

        //public async Task<IActionResult> Edit(int id)
        //{
        //    var response = await _httpClient.GetAsync($"/{id}");
        //    if (!response.IsSuccessStatusCode) return NotFound();

        //    var json = await response.Content.ReadAsStringAsync();
        //    var post = JsonConvert.DeserializeObject<BlogPostViewModel>(json);
        //    return View(post);
        //}

        //[HttpPost]
        //public async Task<IActionResult> Edit(int id, BlogPostViewModel model)
        //{
        //    var json = JsonConvert.SerializeObject(new { model.Title, model.Content });
        //    var content = new StringContent(json, Encoding.UTF8, "application/json");
        //    var response = await _httpClient.PutAsync($"/{id}", content);

        //    if (response.IsSuccessStatusCode) return RedirectToAction("Index");
        //    return View(model);
        //}

        //public async Task<IActionResult> Delete(int id)
        //{
        //    var response = await _httpClient.GetAsync($"/{id}");
        //    if (!response.IsSuccessStatusCode) return NotFound();

        //    var json = await response.Content.ReadAsStringAsync();
        //    var post = JsonConvert.DeserializeObject<BlogPostViewModel>(json);
        //    return View(post);
        //}

        //[HttpPost, ActionName("Delete")]
        //public async Task<IActionResult> ConfirmDelete(int id)
        //{
        //    var response = await _httpClient.DeleteAsync($"/{id}");
        //    if (response.IsSuccessStatusCode) return RedirectToAction("Index");
        //    return RedirectToAction("Delete", new { id });
        //}
        public IActionResult Success()
        {
            return View();
        }
    }
}
