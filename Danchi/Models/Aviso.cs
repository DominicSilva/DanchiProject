using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Danchi.Models
{
    public class Aviso
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdAviso { get; set; }

        [Required]
        [StringLength(80)]
        [Display(Name = "Titulo")]
        public string Titulo { get; set; }

        [Required]
        [Display(Name = "Descripción")]
        [DataType(DataType.MultilineText)]
        public string Descripcion { get; set; }

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
    }
}