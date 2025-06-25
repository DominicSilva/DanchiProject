using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class Evento
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdEvento { get; set; }

        [Required]
        [Display(Name = "Titulo")]
        public string Titulo { get; set; }

        [Required]
        [Display(Name = "Descripción")]
        [DataType(DataType.MultilineText)]
        public string Descripcion { get; set; }

        [Required]
        [Display(Name = "Fecha de Evento")]
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:dd/MM/yyyy}", ApplyFormatInEditMode = true)]
        public DateTime FechaEvento { get; set; }

        [Required]
        [Display(Name = "Hora de Inicio")]
        [DataType(DataType.Time)]
        public TimeSpan HoraInicio { get; set; }

        [Required]
        [Display(Name = "Hora de Finalización")]
        [DataType(DataType.Time)]
        public TimeSpan HoraFin { get; set; }

        [Required]
        [Display(Name = "Lugar")]
        public string Lugar { get; set; }

        [Required]
        [Display(Name = "Estado")]
        public bool Estado { get; set; }

        [ScaffoldColumn(false)]
        [Display(Name = "Fecha de Creación")]
        public DateTime FechaCreacion { get; set; } = DateTime.Now;

        [ScaffoldColumn(false)]
        public int UsuarioCreacion { get; set; }

        [ScaffoldColumn(false)]
        public DateTime? FechaModificacion { get; set; }

        [ScaffoldColumn(false)]
        public int? UsuarioModificacion { get; set; }

        public virtual ICollection<AsistenciaEvento> AsistenciaEventos { get; set; }

        public Evento()
        {
            Estado = true;
        }
    }
}