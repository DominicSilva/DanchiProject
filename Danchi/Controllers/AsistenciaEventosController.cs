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
    public class AsistenciaEventosController : Controller
    {
        private readonly DanchiDBContext _db;

        public AsistenciaEventosController(DanchiDBContext db)
        {
            _db = db;
        }

        public async Task<ActionResult> Index()
        {
            var asistenciaEventos = _db.AsistenciaEventos.Include(a => a.Evento).Include(a => a.Usuario);
            return View(await asistenciaEventos.ToListAsync());
        }

        public ActionResult Create()
        {
            ViewBag.IdEvento = new SelectList(_db.Eventos, "IdEvento", "Titulo");
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(AsistenciaEvento asistenciaEvento)
        {
            if (ModelState.IsValid)
            {
                _db.AsistenciaEventos.Add(asistenciaEvento);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Asistencia a evento confirmada exitosamente";
                return RedirectToAction("Index");
            }

            ViewBag.IdEvento = new SelectList(_db.Eventos, "IdEvento", "Titulo", asistenciaEvento.IdEvento);
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", asistenciaEvento.IdUsuario);
            return View(asistenciaEvento);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AsistenciaEvento asistenciaEvento = await _db.AsistenciaEventos.FindAsync(id);
            if (asistenciaEvento == null)
            {
                return HttpNotFound();
            }
            ViewBag.IdEvento = new SelectList(_db.Eventos, "IdEvento", "Titulo", asistenciaEvento.IdEvento);
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", asistenciaEvento.IdUsuario);
            return View(asistenciaEvento);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(AsistenciaEvento asistenciaEvento)
        {
            if (ModelState.IsValid)
            {
                _db.Entry(asistenciaEvento).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Asistencia a evento actualizada exitosamente";
                return RedirectToAction("Index");
            }
            ViewBag.IdEvento = new SelectList(_db.Eventos, "IdEvento", "Titulo", asistenciaEvento.IdEvento);
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", asistenciaEvento.IdUsuario);
            return View(asistenciaEvento);
        }

        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            AsistenciaEvento asistenciaEvento = await _db.AsistenciaEventos.FindAsync(id);
            if (asistenciaEvento == null)
            {
                return HttpNotFound();
            }
            return View(asistenciaEvento);
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
