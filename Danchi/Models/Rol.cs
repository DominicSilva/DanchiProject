using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Danchi.Models
{
    public class Rol
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdRol { get; set; }

        [Display(Name = "Rol")]
        [Required]
        public string DescripcionRol { get; set; }

        [HiddenInput]
        public DateTime FechaCreacion { get; set; } = DateTime.Now;

        [HiddenInput]
        public int UsuarioCreacion { get; set; }

        [HiddenInput]
        public DateTime? FechaModificacion { get; set; }

        [HiddenInput]
        public int? UsuarioModificacion { get; set; }

        public virtual ICollection<Usuario> Usuarios { get; set; }
    }
}