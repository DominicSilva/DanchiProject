using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class UsuarioDashboardViewModel
    {
        public string NombreCompleto { get; set; }

        public List<Mensaje> MensajesNoLeidos { get; set; }

        public UsuarioDashboardViewModel()
        {
            MensajesNoLeidos = new List<Mensaje>();
        }
    }
}