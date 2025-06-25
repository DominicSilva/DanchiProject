using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class Propietario
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdPropietario { get; set; }

        [Required]
        [Display(Name = "Tipo de Documento")]
        public int IdTipoDocumento { get; set; }

        public virtual TiposDocumento TiposDocumento { get; set; }

        [Required]
        [StringLength(11)]
        [Display(Name = "Numero de Documento")]
        public string NumeroDocumento { get; set; }

        [Required]
        [StringLength(50)]
        [Display(Name = "Apellidos")]
        public string Apellidos { get; set; }

        [Required]
        [StringLength(50)]
        [Display(Name = "Nombres")]
        public string Nombres { get; set; }

        [Required]
        [StringLength(50)]
        [Display(Name = "Correo Electrónico")]
        [EmailAddress]
        public string Correo { get; set; }

        [StringLength(10)]
        [Display(Name = "Teléfono")]
        public string Telefono { get; set; }

        [StringLength(10)]
        [Display(Name = "Celular")]
        public string Celular { get; set; }

        [Required]
        [Display(Name = "Apto")]
        public int IdApto { get; set; }

        public virtual Apto Apto { get; set; }

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