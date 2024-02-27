using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MVCAuthentication.Models;
using MVCAuthentication.ViewModels;
using System.Diagnostics;

namespace MVCAuthentication.Controllers
{
    public class HomeController : Controller
    {
        RoleManager<IdentityRole> _roleManager;       
       
        public HomeController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        private async Task CreateRolesAsync()
        {
            if(! _roleManager.Roles.Any())
            {
                await _roleManager.CreateAsync(new IdentityRole { Name = Roles.ADMIN_ROLE });
                await _roleManager.CreateAsync(new IdentityRole { Name = Roles.USER_ROLE });
            }
        }
        public async Task<IActionResult> IndexAsync()
        {
            await CreateRolesAsync();
            return View();
        }
        public IActionResult LoggedOut()
        {
            return View();
        }
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}