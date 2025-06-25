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
using System.Diagnostics;
using iTextSharp.text.pdf;
using iTextSharp.text;
using System.IO;

namespace Danchi.Controllers
{
    [Authorize]
    public class PropietariosController : Controller
    {
        private readonly DanchiDBContext _db;

        public PropietariosController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            var propietarios = _db.Propietarios.Include(p => p.Apto);
            return View(await propietarios.ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Create()
        {
            ViewBag.IdApto = new SelectList(_db.Aptos, "IdApto", "NombreApto");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Propietario propietario)
        {
            if (ModelState.IsValid)
            {
                propietario.UsuarioCreacion = SessionHelper.UserId.Value;
                _db.Propietarios.Add(propietario);
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Propietario guardado exitosamente";
                return RedirectToAction("Index");
            }

            ViewBag.IdApto = new SelectList(_db.Aptos, "IdApto", "NombreApto", propietario.IdApto);
            return View(propietario);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Propietario propietario = await _db.Propietarios.FindAsync(id);
            if (propietario == null)
            {
                return HttpNotFound();
            }
            ViewBag.IdApto = new SelectList(_db.Aptos, "IdApto", "NombreApto", propietario.IdApto);
            return View(propietario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Propietario propietario)
        {
            if (ModelState.IsValid)
            {
                propietario.UsuarioModificacion = SessionHelper.UserId.Value;
                propietario.FechaModificacion = DateTime.Now;
                _db.Entry(propietario).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["AlertMessage"] = "Propietario actualizado exitosamente";
                return RedirectToAction("Index");
            }
            ViewBag.IdApto = new SelectList(_db.Aptos, "IdApto", "NombreApto", propietario.IdApto);
            return View(propietario);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Propietario propietario = await _db.Propietarios.FindAsync(id);
            if (propietario == null)
            {
                return HttpNotFound();
            }
            return View(propietario);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Propietario propietario = await _db.Propietarios.FindAsync(id);
            _db.Propietarios.Remove(propietario);
            await _db.SaveChangesAsync();
            TempData["AlertMessage"] = "Propietario eliminado exitosamente";
            return RedirectToAction("Index");
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> ExportarEventosPDF()
        {
            var propietarios = await _db.Propietarios.Include(x => x.TiposDocumento).Include(x => x.Apto).Include(y => y.Apto.Torre).OrderByDescending(z => z.Apto.Torre.IdTorre).ToListAsync();

            MemoryStream workStream = new MemoryStream();
            Document document = new Document(PageSize.LETTER, 25, 25, 25, 25);
            PdfWriter.GetInstance(document, workStream).CloseStream = false;
            document.Open();

            // Título principal
            var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
            document.Add(new Paragraph("Lista de Propietarios", titleFont));
            document.Add(new Paragraph("\n"));

            foreach (var grupo in propietarios)
            {
                // Tabla
                PdfPTable table = new PdfPTable(7); // 7 columnas
                table.WidthPercentage = 100;

                // Encabezados
                string[] headers = { "Torre", "Apto", "Tipo Documento", "Número Documento", "Apellidos", "Nombres", "Telefono" };
                foreach (var header in headers)
                {
                    PdfPCell cell = new PdfPCell(new Phrase(header));
                    cell.BackgroundColor = new BaseColor(230, 230, 250);
                    table.AddCell(cell);
                }

                table.AddCell(grupo.Apto.Torre.NombreTorre);
                table.AddCell(grupo.Apto.NombreApto);
                table.AddCell(grupo.TiposDocumento.Abreviatura);
                table.AddCell(grupo.NumeroDocumento);
                table.AddCell(grupo.Apellidos);
                table.AddCell(grupo.Nombres);
                table.AddCell(string.IsNullOrWhiteSpace(grupo.Telefono) ? grupo.Celular : grupo.Telefono);

                document.Add(table);
                document.Add(new Paragraph("\n")); // Espacio entre grupos
            }

            document.Close();
            workStream.Position = 0;

            return File(workStream, "application/pdf", "Propietarios.pdf");
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
