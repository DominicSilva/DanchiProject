using System;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Danchi.Models;
using Danchi.Context;
using Danchi.Security;
using Danchi.Services;
using Newtonsoft.Json;
using System.Web.Security;
using Danchi.Utils;
using System.Collections.Generic;
using System.Net;
using System.Data.Entity;

namespace Danchi.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly DanchiDBContext _db;
        private readonly IPasswordEncripter _passwordEncripter;
        private readonly IAuthorizationService _authService;

        public AccountController(DanchiDBContext db, IPasswordEncripter passwordEncripter, IAuthorizationService authService)
        {
            _db = db;
            _passwordEncripter = passwordEncripter;
            _authService = authService;
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            var usuarios = _db.Usuarios.Include(u => u.Rol);
            return View(await usuarios.ToListAsync());
        }

        [AllowAnonymous]
        public ActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(Login model)
        {
            if (!ModelState.IsValid)
            {
                return RedirectToAction("Login", "Account");
            }

            Usuario usuario = new Usuario();
            var result = _authService.Auth(model.Email, model.Password, out usuario);
            switch (result)
            {
                case AuthResults.Success:
                    CookieUpdate(usuario);
                    if (SessionHelper.Rol == "Administrador")
                    {
                        return Redirect(Url.Action("Index", "Home"));
                    }
                    else
                    {
                        return Redirect(Url.Action("UserView", "Home"));
                    }
                case AuthResults.PasswordNotMatch:
                    TempData["AlertMessage"] = "La Contrasena es incorrecta.";
                    return RedirectToAction("Login", "Account");
                case AuthResults.NotExists:
                    TempData["AlertMessage"] = "El usuario no existe.";
                    return RedirectToAction("Login", "Account");
                default:
                    return RedirectToAction("Login", "Account");
            }
        }

        private void CookieUpdate(Usuario usuario)
        {
            try
            {
                var ticket = new FormsAuthenticationTicket(
                    2,
                    usuario.Correo,
                    DateTime.Now,
                    DateTime.Now.AddMinutes(FormsAuthentication.Timeout.TotalMinutes),
                    false,
                    usuario.Rol.DescripcionRol
                );

                var encryptedTicket = FormsAuthentication.Encrypt(ticket);
                var authCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
                Response.Cookies.Add(authCookie);

                SessionHelper.NombreCompleto = usuario.Nombres + " " + usuario.Apellidos;
                SessionHelper.UserName = usuario.Correo;
                SessionHelper.Rol = usuario.Rol.DescripcionRol;
                SessionHelper.UserId = usuario.IdUsuario;
            }
            catch (Exception ex)
            {
                throw new Exception("Error al crear la cookie de autenticación: " + ex.Message);
            }
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            Session.RemoveAll();
            Session.Clear();
            FormsAuthentication.SignOut();
            return RedirectToAction("Inicio", "Home");
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Register()
        {
            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(Usuario model)
        {
            if (ModelState.IsValid)
            {
                var hash = new List<byte[]>();
                model.Contrasena = _passwordEncripter.Encript(model.Contrasena, out hash);
                model.HashKey = hash[0];
                model.HashIV = hash[1];
                model.UsuarioCreacion = SessionHelper.UserId.Value;

                _db.Usuarios.Add(model);
                await _db.SaveChangesAsync();

                TempData["SuccessMessage"] = "Usuario creado correctamente";
                return RedirectToAction("Index");
            }
            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View(model);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if ((SessionHelper.Rol != "Administrador") && (id != SessionHelper.UserId.Value))
            {
                return RedirectToAction("Unauthorized", "Error");
            }

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Usuario usuario = await _db.Usuarios.FindAsync(id);
            if (usuario == null)
            {
                return HttpNotFound();
            }
            ViewBag.Rol = await _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToListAsync();
            return View(usuario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Usuario model)
        {
            if (ModelState.IsValid)
            {
                if (!string.IsNullOrEmpty(model.NuevaContrasena))
                {
                    if (model.HashKey == null && model.HashIV == null)
                    {
                        var hash = new List<byte[]>();
                        model.Contrasena = _passwordEncripter.Encript(model.NuevaContrasena, out hash);
                        model.HashKey = hash[0];
                        model.HashIV = hash[1];
                    }
                    else
                    {
                        model.Contrasena = _passwordEncripter.Encript(model.NuevaContrasena, new List<byte[]>()
                          .AddHash(model.HashKey)
                          .AddHash(model.HashIV));
                    }
                }
                model.FechaModificacion = DateTime.Now;
                model.UsuarioModificacion = SessionHelper.UserId;

                _db.Entry(model).State = EntityState.Modified;
                await _db.SaveChangesAsync();

                TempData["SuccessMessage"] = "Usuario actualizado correctamente";
                return RedirectToAction("Index");
            }

            ViewBag.Rol = _db.Rol.Select(r => new SelectListItem { Value = r.IdRol.ToString(), Text = r.DescripcionRol }).ToList();
            return View(model);
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Usuario usuario = _db.Usuarios.Find(id);
            if (usuario == null)
            {
                return HttpNotFound();
            }
            return View(usuario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Usuario usuario = _db.Usuarios.Find(id);
            _db.Usuarios.Remove(usuario);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Usuario eliminado correctamente";
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}