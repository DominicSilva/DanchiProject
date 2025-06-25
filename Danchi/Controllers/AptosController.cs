using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using System.Net;
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
    public class AptosController : Controller
    {
        private readonly DanchiDBContext _db;

        public AptosController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            var aptos = _db.Aptos.Include(a => a.Torre);
            return View(await aptos.ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Create()
        {
            ViewBag.IdTorre = new SelectList(_db.Torres, "IdTorre", "NombreTorre");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Apto apto)
        {
            if (ModelState.IsValid)
            {
                apto.UsuarioCreacion = SessionHelper.UserId.Value;
                _db.Aptos.Add(apto);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Apto guardado exitosamente";
                return RedirectToAction("Index");
            }

            ViewBag.IdTorre = new SelectList(_db.Torres, "IdTorre", "NombreTorre", apto.IdTorre);
            return View(apto);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Apto apto = await _db.Aptos.FindAsync(id);
            if (apto == null)
            {
                return HttpNotFound();
            }
            ViewBag.IdTorre = new SelectList(_db.Torres, "IdTorre", "NombreTorre", apto.IdTorre);
            return View(apto);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Apto apto)
        {
            if (ModelState.IsValid)
            {
                apto.UsuarioModificacion = SessionHelper.UserId.Value;
                apto.FechaModificacion = DateTime.Now;
                _db.Entry(apto).State = EntityState.Modified;
                TempData["SuccessMessage"] = "Apto actualizado exitosamente";
                await _db.SaveChangesAsync();
                return RedirectToAction("Index");
            }
            ViewBag.IdTorre = new SelectList(_db.Torres, "IdTorre", "NombreTorre", apto.IdTorre);
            return View(apto);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Apto apto = await _db.Aptos.FindAsync(id);
            if (apto == null)
            {
                return HttpNotFound();
            }
            return View(apto);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Apto apto = await _db.Aptos.FindAsync(id);
            _db.Aptos.Remove(apto);
            TempData["SuccessMessage"] = "Apto eliminado exitosamente";
            await _db.SaveChangesAsync();
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
