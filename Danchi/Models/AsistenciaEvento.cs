using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class AsistenciaEvento
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [ScaffoldColumn(false)]
        public int IdAsistencia { get; set; }

        [ScaffoldColumn(false)]
        public int IdUsuario { get; set; }

        [Required]
        [Display(Name = "Evento")]
        public int IdEvento { get; set; }

        [Required]
        [Display(Name = "¿Confirmado?")]
        public bool Confirmado { get; set; }

        [ScaffoldColumn(false)]
        public DateTime FechaConfirmacion { get; set; } = DateTime.Now;

        public virtual Usuario Usuario { get; set; }

        public virtual Evento Evento { get; set; }
    }
}