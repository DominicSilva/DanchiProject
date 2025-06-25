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
using Danchi.Utils;

namespace Danchi.Controllers
{
    [Authorize]
    public class AvisosController : Controller
    {
        private readonly DanchiDBContext _db;

        public AvisosController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Residente")]
        public async Task<ActionResult> AvisoView()
        {
            return View(await _db.Avisos.Where(x => x.Estado == true).ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            return View(await _db.Avisos.ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Aviso aviso)
        {
            if (ModelState.IsValid)
            {
                aviso.UsuarioCreacion = SessionHelper.UserId.Value;
                _db.Avisos.Add(aviso);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Aviso guardado exitosamente";
                return RedirectToAction("Index");
            }

            return View(aviso);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Aviso aviso = await _db.Avisos.FindAsync(id);
            if (aviso == null)
            {
                return HttpNotFound();
            }
            return View(aviso);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Aviso aviso)
        {
            if (ModelState.IsValid)
            {
                aviso.UsuarioModificacion = SessionHelper.UserId;
                aviso.FechaModificacion = DateTime.Now;
                _db.Entry(aviso).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Aviso actualizado exitosamente";
                return RedirectToAction("Index");
            }
            return View(aviso);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Aviso aviso = await _db.Avisos.FindAsync(id);
            if (aviso == null)
            {
                return HttpNotFound();
            }
            return View(aviso);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Aviso aviso = await _db.Avisos.FindAsync(id);
            _db.Avisos.Remove(aviso);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Aviso eliminado exitosamente";
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
