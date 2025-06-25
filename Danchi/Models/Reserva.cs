using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class Reserva
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdReserva { get; set; }

        [ScaffoldColumn(false)]
        public int IdUsuario { get; set; }

        [Display(Name = "Zona")]
        [Required]
        public string Zona { get; set; }

        [Display(Name = "Fecha de Reserva")]
        [Required]
        [DataType(DataType.Date)]
        public DateTime FechaReserva { get; set; }

        [Display(Name = "Hora de Inicio")]
        [Required]
        [DataType(DataType.Time)]
        public TimeSpan HoraInicio { get; set; }

        [Display(Name = "Hora de Finalización")]
        [Required]
        [DataType(DataType.Time)]
        public TimeSpan HoraFin { get; set; }

        [Display(Name = "Número de Invitados")]
        [Required]
        public int NumInvitados { get; set; }

        [ScaffoldColumn(false)]
        public DateTime FechaCreacion { get; set; } = DateTime.Now;

        [ScaffoldColumn(false)]
        public int UsuarioCreacion { get; set; }

        [ScaffoldColumn(false)]
        public DateTime? FechaModificacion { get; set; }

        [ScaffoldColumn(false)]
        public int? UsuarioModificacion { get; set; }

        // Propiedad de navegación
        public virtual Usuario Usuario { get; set; }
    }
}