using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Web;

namespace Danchi.Models
{
    public class Mensaje
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdMensaje { get; set; }

        [Required]
        public int IdEmisor { get; set; }

        [Required]
        [Display(Name = "Para")]
        public int IdReceptor { get; set; }

        [Required]
        [Display(Name = "Asunto")]
        public string Asunto { get; set; }

        [Required]
        [Display(Name = "Descripción")]
        public string Descripcion { get; set; }

        public DateTime FechaEnvio { get; set; } = DateTime.Now;

        [Display(Name = "Archivo Adjunto (Opcional)")]
        public string ArchivoAdjunto { get; set; }

        public bool Leido { get; set; }

        public int? MensajePadreId { get; set; }

        // Relaciones de navegación
        [ForeignKey("IdEmisor")]
        public virtual Usuario Emisor { get; set; }
        [ForeignKey("IdReceptor")]
        public virtual Usuario Receptor { get; set; }
        public virtual Mensaje MensajePadre { get; set; }
        public virtual ICollection<Mensaje> Respuestas { get; set; }
    }
}