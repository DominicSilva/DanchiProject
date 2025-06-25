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

namespace Danchi.Controllers
{
    [Authorize]
    public class TiposDocumentoController : Controller
    {
        private readonly DanchiDBContext _db;

        public TiposDocumentoController(DanchiDBContext db)
        {
            _db = db;
        }

        public async Task<ActionResult> Index()
        {
            return View(await _db.TiposDocumento.ToListAsync());
        }

        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(TiposDocumento tiposDocumento)
        {
            if (ModelState.IsValid)
            {
                _db.TiposDocumento.Add(tiposDocumento);
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Tipo de documento guardado exitosamente";
                return RedirectToAction("Index");
            }

            return View(tiposDocumento);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TiposDocumento tiposDocumento = await _db.TiposDocumento.FindAsync(id);
            if (tiposDocumento == null)
            {
                return HttpNotFound();
            }
            return View(tiposDocumento);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(TiposDocumento tiposDocumento)
        {
            if (ModelState.IsValid)
            {
                _db.Entry(tiposDocumento).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Tipo de documento actualizado exitosamente";
                return RedirectToAction("Index");
            }
            return View(tiposDocumento);
        }

        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TiposDocumento tiposDocumento = await _db.TiposDocumento.FindAsync(id);
            if (tiposDocumento == null)
            {
                return HttpNotFound();
            }
            return View(tiposDocumento);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            TiposDocumento tiposDocumento = await _db.TiposDocumento.FindAsync(id);
            _db.TiposDocumento.Remove(tiposDocumento);
            await _db.SaveChangesAsync();
            TempData["AlertMessage"] = "Tipo de documento eliminado exitosamente";
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
