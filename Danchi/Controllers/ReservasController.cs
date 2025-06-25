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
    public class ReservasController : Controller
    {
        private readonly DanchiDBContext _db;

        public ReservasController(DanchiDBContext db)
        {
            _db = db;
        }

        public async Task<ActionResult> Index()
        {
            var reservas = _db.Reservas.Include(r => r.Usuario);
            return View(await reservas.ToListAsync());
        }

        public async Task<ActionResult> Details(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Reserva reserva = await _db.Reservas.FindAsync(id);
            if (reserva == null)
            {
                return HttpNotFound();
            }
            return View(reserva);
        }

        public ActionResult Create()
        {
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(Reserva reserva)
        {
            if (ModelState.IsValid)
            {
                _db.Reservas.Add(reserva);
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Reserva guardada exitosamente";
                return RedirectToAction("Index");
            }

            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", reserva.IdUsuario);
            return View(reserva);
        }

        public async Task<ActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Reserva reserva = await _db.Reservas.FindAsync(id);
            if (reserva == null)
            {
                return HttpNotFound();
            }
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", reserva.IdUsuario);
            return View(reserva);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(Reserva reserva)
        {
            if (ModelState.IsValid)
            {
                _db.Entry(reserva).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                TempData["SuccessMessage"] = "Reserva actualizada exitosamente";
                return RedirectToAction("Index");
            }
            ViewBag.IdUsuario = new SelectList(_db.Usuarios, "IdUsuario", "Nombres", reserva.IdUsuario);
            return View(reserva);
        }

        public async Task<ActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Reserva reserva = await _db.Reservas.FindAsync(id);
            if (reserva == null)
            {
                return HttpNotFound();
            }
            return View(reserva);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(int id)
        {
            Reserva reserva = await _db.Reservas.FindAsync(id);
            _db.Reservas.Remove(reserva);
            await _db.SaveChangesAsync();
            TempData["SuccessMessage"] = "Reserva eliminada exitosamente";
            return RedirectToAction("Index");
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> ExportarEventosPDF()
        {
            var reservas = await _db.Reservas.OrderBy(e => e.FechaReserva).Include(x => x.Usuario).ToListAsync();
            var reservasPorMes = reservas.GroupBy(e => new { e.FechaReserva.Year, e.FechaReserva.Month }).OrderBy(g => g.Key.Year).ThenBy(g => g.Key.Month);

            MemoryStream workStream = new MemoryStream();
            Document document = new Document(PageSize.LETTER, 25, 25, 25, 25);
            PdfWriter.GetInstance(document, workStream).CloseStream = false;
            document.Open();

            // Título principal
            var titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
            document.Add(new Paragraph("Lista de Reservas Por Mes", titleFont));
            document.Add(new Paragraph("\n"));

            foreach (var grupo in reservasPorMes)
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
                string[] headers = { "ID", "Zona", "Usuario Reserva", "Fecha Reserva", "Hora Inicio", "Hora Fin", "Numero de Invitados" };
                foreach (var header in headers)
                {
                    PdfPCell cell = new PdfPCell(new Phrase(header));
                    cell.BackgroundColor = new BaseColor(230, 230, 250);
                    table.AddCell(cell);
                }

                foreach (var item in grupo)
                {
                    table.AddCell(item.IdReserva.ToString());
                    table.AddCell(item.Zona);
                    table.AddCell(item.Usuario.Nombres + ' ' + item.Usuario.Apellidos);
                    table.AddCell(item.FechaReserva.ToString("dd/MM/yyyy"));
                    table.AddCell(item.HoraInicio.ToString(@"hh\:mm"));
                    table.AddCell(item.HoraFin.ToString(@"hh\:mm"));
                    table.AddCell(item.NumInvitados.ToString());
                }

                document.Add(table);
                document.Add(new Paragraph("\n")); // Espacio entre grupos
            }

            document.Close();
            workStream.Position = 0;

            return File(workStream, "application/pdf", "Reservas_Por_Mes.pdf");
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
