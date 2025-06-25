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
using System.IO;
using Danchi.Utils;
using System.Web.Services.Description;

namespace Danchi.Controllers
{
    [Authorize]
    public class MensajesController : Controller
    {
        private readonly DanchiDBContext _db;

        public MensajesController(DanchiDBContext db)
        {
            _db = db;
        }

        public async Task<ActionResult> Index()
        {
            int userId = SessionHelper.UserId ?? 0;
            var recibidos = await _db.Mensajes.Where(m => m.IdReceptor == userId).Include(m => m.Emisor).ToListAsync();
            var enviados = await _db.Mensajes.Where(m => m.IdEmisor == userId).Include(m => m.Receptor).ToListAsync();

            var model = new BandejaViewModel
            {
                Recibidos = recibidos,
                Enviados = enviados
            };

            return View(model);
        }
        //CREO Q TAMBIEN LO CAMBIEEE
        public ActionResult Reply(int id)
        {
            var mensajeOriginal = _db.Mensajes
                .Include(m => m.Emisor)
                .FirstOrDefault(m => m.IdMensaje == id);

            if (mensajeOriginal == null)
                return HttpNotFound();

            var usuarioActualId = SessionHelper.UserId ?? 0;
            var receptor = _db.Usuarios.Find(mensajeOriginal.IdEmisor); // El emisor original es ahora el receptor

            var reply = new Mensaje
            {
                IdReceptor = mensajeOriginal.IdEmisor,
                IdEmisor = usuarioActualId,
                Asunto = "Re: " + mensajeOriginal.Asunto,
                MensajePadreId = mensajeOriginal.IdMensaje,
                Receptor = receptor // Esta es la clave para que funcione la vista
            };

            return View(reply);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Reply(Mensaje model, HttpPostedFileBase archivo)
        {
            if (!ModelState.IsValid) return View(model);

            model.IdEmisor = SessionHelper.UserId.Value;
            model.FechaEnvio = DateTime.Now;

            if (archivo != null && archivo.ContentLength > 0)
            {
                using (var reader = new BinaryReader(archivo.InputStream))
                {
                    var fileBytes = reader.ReadBytes(archivo.ContentLength);
                    var base64 = Convert.ToBase64String(fileBytes);
                    model.ArchivoAdjunto = $"{archivo.FileName}|{base64}";
                }
            }

            _db.Mensajes.Add(model);
            _db.SaveChanges();
            TempData["SuccessMessage"] = "Mensaje enviado exitosamente";
            return RedirectToAction("Index");
        }

        public async Task<ActionResult> Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            var mensaje = await _db.Mensajes.Include("Emisor").Include("Receptor").Include("Respuestas").FirstOrDefaultAsync(m => m.IdMensaje == id);

            if (mensaje == null)
            {
                return HttpNotFound();
            }

            int userId = SessionHelper.UserId.Value;

            if (mensaje.IdReceptor == userId && !mensaje.Leido)
            {
                mensaje.Leido = true;
                _db.Entry(mensaje).State = EntityState.Modified;
                await _db.SaveChangesAsync();
            }
            return View(mensaje);
        }
        //LO QUE CAMBIEEEEEE
        public ActionResult Create()
        {
            int usuarioActualId = SessionHelper.UserId ?? 0;
            var usuarioActual = _db.Usuarios.Find(usuarioActualId);

            List<Usuario> receptores;

            if (usuarioActual.IdRol == 1) // 1 = Admin
            {
                // Admin puede ver a todos, excepto a sí mismo
                receptores = _db.Usuarios
                    .Where(u => u.IdUsuario != usuarioActualId)
                    .ToList();
            }
            else
            {
                // Residente solo puede ver al admin
                receptores = _db.Usuarios
                    .Where(u => u.IdRol == 1) // admin
                    .ToList();
            }

            ViewBag.IdReceptor = new SelectList(receptores, "IdUsuario", "Correo");

            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Mensaje mensaje, HttpPostedFileBase archivo)
        {
            if (ModelState.IsValid)
            {
                mensaje.IdEmisor = SessionHelper.UserId.Value;
                mensaje.FechaEnvio = DateTime.Now;

                if (archivo != null && archivo.ContentLength > 0)
                {
                    using (var reader = new BinaryReader(archivo.InputStream))
                    {
                        var fileBytes = reader.ReadBytes(archivo.ContentLength);
                        var base64 = Convert.ToBase64String(fileBytes);
                        mensaje.ArchivoAdjunto = $"{archivo.FileName}|{base64}";
                    }
                }

                _db.Mensajes.Add(mensaje);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Mensaje enviado exitosamente";
                return RedirectToAction("Index");
            }

            ViewBag.IdReceptor = new SelectList(_db.Usuarios, "IdUsuario", "Correo", mensaje.IdReceptor);
            return View(mensaje);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Mensaje mensaje = await _db.Mensajes.FindAsync(id);
            if (mensaje == null)
            {
                return HttpNotFound();
            }
            return View(mensaje);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Mensaje mensaje, HttpPostedFileBase archivo)
        {
            if (ModelState.IsValid)
            {
                if (archivo != null && archivo.ContentLength > 0)
                {
                    using (var reader = new BinaryReader(archivo.InputStream))
                    {
                        var fileBytes = reader.ReadBytes(archivo.ContentLength);
                        var base64 = Convert.ToBase64String(fileBytes);
                        mensaje.ArchivoAdjunto = $"{archivo.FileName}|{base64}";
                    }
                }

                _db.Entry(mensaje).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Mensaje actualizado exitosamente";
                return RedirectToAction("Index");
            }
            return View(mensaje);
        }

        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Mensaje mensaje = await _db.Mensajes.FindAsync(id);
            if (mensaje == null)
            {
                return HttpNotFound();
            }
            return View(mensaje);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Mensaje mensaje = await _db.Mensajes.FindAsync(id);
            _db.Mensajes.Remove(mensaje);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Mensaje eliminado exitosamente";
            return RedirectToAction("Index");
        }

        public async Task<ActionResult> DescargarArchivo(int id)
        {
            var mensaje = await _db.Mensajes.FindAsync(id);
            if (mensaje == null || string.IsNullOrEmpty(mensaje.ArchivoAdjunto))
                return HttpNotFound();

            // archivo almacenado como: "nombre.pdf|BASE64"
            var partes = mensaje.ArchivoAdjunto.Split('|');
            if (partes.Length != 2)
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);

            var nombre = partes[0];
            var base64 = partes[1];
            var bytes = Convert.FromBase64String(base64);

            return File(bytes, MimeMapping.GetMimeMapping(nombre), nombre);
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
