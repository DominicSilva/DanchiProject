using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Danchi.Context;
using Danchi.Models;
using Danchi.Security;
using Danchi.Services;
using Danchi.Utils;

namespace Danchi.Controllers
{
    [Authorize]
    public class TorresController : Controller
    {
        private readonly DanchiDBContext _db;

        public TorresController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            return View(await _db.Torres.ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Torre torre)
        {
            if (ModelState.IsValid)
            {
                torre.UsuarioCreacion = SessionHelper.UserId.Value;
                _db.Torres.Add(torre);
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Torre guardada exitosamente";
                return RedirectToAction("Index");
            }

            return View(torre);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Torre torre = await _db.Torres.FindAsync(id);
            if (torre == null)
            {
                return HttpNotFound();
            }
            return View(torre);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Torre torre)
        {
            if (ModelState.IsValid)
            {
                torre.UsuarioModificacion = SessionHelper.UserId.Value;
                torre.FechaModificacion = DateTime.Now;
                _db.Entry(torre).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Torre actualizada exitosamente";
                return RedirectToAction("Index");
            }
            return View(torre);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Torre torre = await _db.Torres.FindAsync(id);
            if (torre == null)
            {
                return HttpNotFound();
            }
            return View(torre);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Torre torre = _db.Torres.Find(id);
            _db.Torres.Remove(torre);
            await _db.SaveChangesAsync();
            TempData["AlertMessage"] = "Torre eliminada exitosamente";
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
