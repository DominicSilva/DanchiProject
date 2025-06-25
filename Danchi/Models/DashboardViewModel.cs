using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class DashboardViewModel
    {
        public int TotalTorres { get; set; }
        public int TotalAptos { get; set; }
        public int TotalPropietarios { get; set; }

        public Dictionary<string, int> MensajesEnviadosPorMes { get; set; }
        public Dictionary<string, int> MensajesRecibidosPorMes { get; set; }
        public Dictionary<string, int> ReservasPorMes { get; set; }
        public Dictionary<string, int> EventosPorMes { get; set; }
    }
}