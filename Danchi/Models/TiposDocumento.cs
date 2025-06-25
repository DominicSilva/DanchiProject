using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class TiposDocumento
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdTipoDocumento { get; set; }

        [Display(Name = "Nombre Tipo Documento")]
        [Required]
        public string NombreTipoDocumento { get; set; }

        [Display(Name = "Abreviatura")]
        [Required]
        public string Abreviatura { get; set; }

        public virtual ICollection<Propietario> Propietarios { get; set; }
    }
}