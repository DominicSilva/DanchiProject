using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Danchi.Models
{
    public class Torre
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [HiddenInput]
        public int IdTorre { get; set; }

        [Required]
        [StringLength(50)]
        [Display(Name = "Nombre o Distinción Torre")]
        public string NombreTorre { get; set; }

        [HiddenInput]
        [Display(Name = "Fecha Creación")]
        public DateTime FechaCreacion { get; set; } = DateTime.Now;

        [HiddenInput]
        [Display(Name = "Usuario Creación")]
        public int UsuarioCreacion { get; set; }

        [HiddenInput]
        public DateTime? FechaModificacion { get; set; }

        [HiddenInput]
        public int? UsuarioModificacion { get; set; }

        public virtual ICollection<Apto> Aptos { get; set; }
    }
}