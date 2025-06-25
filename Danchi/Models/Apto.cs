using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Danchi.Models
{
    public class Apto
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdApto { get; set; }

        [Required]
        [StringLength(50)]
        [Display(Name = "Nombre o Distinción Apto")]
        public string NombreApto { get; set; }

        [Required]
        [Display(Name = "Torre")]
        public int IdTorre { get; set; }

        public virtual Torre Torre { get; set; }

        public virtual ICollection<Propietario> Propietarios { get; set; }

        [HiddenInput]
        [Display(Name = "Fecha Creación")]
        public DateTime FechaCreacion { get; set; } = DateTime.Now;

        [HiddenInput]
        public int UsuarioCreacion { get; set; }

        [HiddenInput]
        public DateTime? FechaModificacion { get; set; }

        [HiddenInput]
        public int? UsuarioModificacion { get; set; }
    }
}