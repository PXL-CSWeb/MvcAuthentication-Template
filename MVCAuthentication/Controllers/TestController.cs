using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace MVCAuthentication.Controllers
{
    [Authorize]
    public class TestController : Controller
    {
        SignInManager<IdentityUser> _manager;
        public TestController(SignInManager<IdentityUser> manager)
        {
            _manager = manager;
        }
        [HttpGet] 
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> LogoutAsync()
        {
            await _manager.SignOutAsync();
            return RedirectToAction("LoggedOut", "Home");
        }
    }
}
