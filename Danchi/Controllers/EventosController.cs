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
using iTextSharp.text.pdf;
using iTextSharp.text;
using System.IO;

namespace Danchi.Controllers
{
    [Authorize]
    public class EventosController : Controller
    {
        private readonly DanchiDBContext _db;

        public EventosController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Residente")]
        public async Task<ActionResult> EventoView()
        {
            return View(await _db.Eventos.Where(x => x.Estado == true).ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            return View(await _db.Eventos.ToListAsync());
        }

        [AuthorizeRole("Administrador")]
        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Evento evento)
        {
            if (ModelState.IsValid)
            {
                evento.UsuarioCreacion = SessionHelper.UserId.Value;
                _db.Eventos.Add(evento);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Evento guardado exitosamente";
                return RedirectToAction("Index");
            }

            return View(evento);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Evento evento = await _db.Eventos.FindAsync(id);
            if (evento == null)
            {
                return HttpNotFound();
            }
            return View(evento);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Evento evento)
        {
            if (ModelState.IsValid)
            {
                evento.UsuarioModificacion = SessionHelper.UserId.Value;
                evento.FechaModificacion = DateTime.Now;
                _db.Entry(evento).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Evento actualizado exitosamente";
                return RedirectToAction("Index");
            }
            return View(evento);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Evento evento = await _db.Eventos.FindAsync(id);
            if (evento == null)
            {
                return HttpNotFound();
            }
            return View(evento);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Evento evento = await _db.Eventos.FindAsync(id);
            _db.Eventos.Remove(evento);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Evento eliminado exitosamente";
            return RedirectToAction("Index");
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> ExportarEventosPDF()
        {
            var eventos = await _db.Eventos.OrderBy(e => e.FechaEvento).ToListAsync();
            var eventosPorMes = eventos.GroupBy(e => new { e.FechaEvento.Year, e.FechaEvento.Month }).OrderBy(g => g.Key.Year).ThenBy(g => g.Key.Month);

            MemoryStream workStream = new MemoryStream();
            Document document = new Document(PageSize.LETTER, 25, 25, 25, 25);
            PdfWriter.GetInstance(document, workStream).CloseStream = false;
            document.Open();

            // Título principal
            var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
            document.Add(new Paragraph("Lista de Eventos Por Mes", titleFont));
            document.Add(new Paragraph("\n"));

            foreach (var grupo in eventosPorMes)
            {
                string nombreMes = new DateTime(grupo.Key.Year, grupo.Key.Month, 1).ToString("MMMM yyyy", new System.Globalization.CultureInfo("es-ES")).ToUpper();

                // Subtítulo del mes
                var monthFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 14);
                document.Add(new Paragraph(nombreMes, monthFont));
                document.Add(new Paragraph("\n"));

                // Tabla
                PdfPTable table = new PdfPTable(7); // 7 columnas
                table.WidthPercentage = 100;

                // Encabezados
                string[] headers = { "Título", "Descripción", "Fecha", "Hora Inicio", "Hora Fin", "Lugar", "Estado" };
                foreach (var header in headers)
                {
                    PdfPCell cell = new PdfPCell(new Phrase(header));
                    cell.BackgroundColor = new BaseColor(230, 230, 250);
                    table.AddCell(cell);
                }

                foreach (var item in grupo)
                {
                    table.AddCell(item.Titulo);
                    table.AddCell(item.Descripcion);
                    table.AddCell(item.FechaEvento.ToString("dd/MM/yyyy"));
                    table.AddCell(item.HoraInicio.ToString(@"hh\:mm"));
                    table.AddCell(item.HoraFin.ToString(@"hh\:mm"));
                    table.AddCell(item.Lugar);
                    table.AddCell(item.Estado ? "Activo" : "Inactivo");
                }

                document.Add(table);
                document.Add(new Paragraph("\n")); // Espacio entre grupos
            }

            document.Close();
            workStream.Position = 0;

            return File(workStream, "application/pdf", "Eventos_Por_Mes.pdf");
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
