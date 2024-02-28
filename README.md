# MvcAuthentication-Facebook-Template

## 1.  Installed packages
* Microsoft.EntityFrameworkCore.Tools
* Microsoft.EntityFrameworkCore.SqlServer
* Microsoft.AspNetCore.Identity.EntityFrameworkCore

## 2.  ViewModels
* UserViewModel

## 3.  Data
* ApplicationDbContext

## 4.  Controllers
* HomeController
* TestController
* AccountController

## 5. Facebook Authentication - Todo

### Add Package
* Microsoft.AspNetCore.Authentication.Facebook

### Facebook settings
* [facebook appsettings](https://developers.facebook.com)
* Create app

### Program.cs
* Service: builder.Services.AddFacebook
* Facebook -> App.Id

### AccountController - FacebookLogin
* redirectUrl
* ExternalAuthenticationProperties
* ChallengeResult

### AccountController - FacebookResponse
* GetExternalLoginInfo()
* ExternalLoginSignin()
* CreateUser()
* AddLogin()

  

