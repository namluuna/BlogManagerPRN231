using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdsController : ControllerBase
    {
        [HttpGet("load-ads")]
        public IActionResult LoadAds()
        {
            var filePath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "ads", "A_digital_image_displays_a_test_advertisement_labe.png");
            var redirectUrl = "https://youtu.be/dQw4w9WgXcQ"; 

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("Ảnh quảng cáo không tồn tại.");
            }

            var fileBytes = System.IO.File.ReadAllBytes(filePath);
            string base64Image = Convert.ToBase64String(fileBytes);
            string imageDataUrl = $"data:image/png;base64,{base64Image}";

            return Ok(new
            {
                ImageData = imageDataUrl,
                RedirectUrl = redirectUrl
            });
        }
    }
}
