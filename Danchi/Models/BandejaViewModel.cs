using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class BandejaViewModel
    {
        public List<Mensaje> Recibidos { get; set; }
        public List<Mensaje> Enviados { get; set; }
    }
}