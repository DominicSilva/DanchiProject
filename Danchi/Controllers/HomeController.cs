using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Danchi.Context;
using Danchi.Models;
using Danchi.Utils;

namespace Danchi.Controllers
{
    public class HomeController : Controller
    {
        private readonly DanchiDBContext _db;

        public HomeController(DanchiDBContext db)
        {
            _db = db;
        }

        [AuthorizeRole("Residente")]
        public async Task<ActionResult> UserView()
        {
            int userId = SessionHelper.UserId.Value;

            var usuario = _db.Usuarios.Find(userId);
            if (usuario == null)
            {
                return HttpNotFound();
            }

            var viewModel = new UsuarioDashboardViewModel
            {
                NombreCompleto = $"{usuario.Nombres} {usuario.Apellidos}",

                MensajesNoLeidos = await _db.Mensajes.Where(m => m.IdReceptor == userId && !m.Leido).OrderByDescending(m => m.FechaEnvio).Take(5).ToListAsync()
            };

            return View(viewModel);
        }

        [AuthorizeRole("Administrador")]
        public async Task<ActionResult> Index()
        {
            var userId = SessionHelper.UserId;

            var model = new DashboardViewModel
            {
                TotalTorres = await _db.Torres.CountAsync(),
                TotalAptos = await _db.Aptos.CountAsync(),
                TotalPropietarios = await _db.Propietarios.CountAsync(),

                MensajesEnviadosPorMes = await _db.Mensajes
                    .Where(m => m.IdEmisor == userId)
                    .GroupBy(m => m.FechaEnvio.Month)
                    .ToDictionaryAsync(g => new DateTime(1, g.Key, 1).ToString("MMMM").ToUpper(), g => g.Count()),

                MensajesRecibidosPorMes = await _db.Mensajes
                    .Where(m => m.IdReceptor == userId)
                    .GroupBy(m => m.FechaEnvio.Month)
                    .ToDictionaryAsync(g => new DateTime(1, g.Key, 1).ToString("MMMM").ToUpper(), g => g.Count()),

                ReservasPorMes = await _db.Reservas
                    .GroupBy(r => r.FechaReserva.Month)
                    .ToDictionaryAsync(g => new DateTime(1, g.Key, 1).ToString("MMMM").ToUpper(), g => g.Count()),

                EventosPorMes = await _db.Eventos
                    .GroupBy(e => e.FechaEvento.Month)
                    .ToDictionaryAsync(g => new DateTime(1, g.Key, 1).ToString("MMMM").ToUpper(), g => g.Count())
            };

            return View(model);
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        public ActionResult Inicio()
        {
            return View();
        }
    }
}