using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity.Core.Common.CommandTrees.ExpressionBuilder;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Newtonsoft.Json;

namespace Danchi.Models
{
    public class Usuario
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int IdUsuario { get; set; }

        [Display(Name = "Nombres")]
        [Required]
        [StringLength(100)]
        public string Nombres { get; set; }

        [Display(Name = "Apellidos")]
        [Required]
        [StringLength(100)]
        public string Apellidos { get; set; }

        [Display(Name = "Correo")]
        [Required]
        [StringLength(100)]
        [EmailAddress]
        public string Correo { get; set; }

        [Display(Name = "Telefono ó Celular")]
        [Required]
        [StringLength(10)]
        public string Telefono { get; set; }

        [Display(Name = "Rol")]
        [Required]
        public int IdRol { get; set; }

        [Display(Name = "Contraseña")]
        [Required]
        [DataType(DataType.Password)]
        [StringLength(50)]
        public string Contrasena { get; set; }

        [Display(Name = "Nueva Contraseña")]
        [DataType(DataType.Password)]
        [NotMapped]
        public string NuevaContrasena { get; set; }

        [HiddenInput]
        public byte[] HashKey { get; set; }

        [HiddenInput]
        public byte[] HashIV { get; set; }

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

        // Relaciones
        [JsonIgnore]
        public virtual Rol Rol { get; set; }

        [JsonIgnore]
        [InverseProperty("Emisor")]
        public virtual ICollection<Mensaje> MensajesEnviados { get; set; }

        [JsonIgnore]
        [InverseProperty("Receptor")]
        public virtual ICollection<Mensaje> MensajesRecibidos { get; set; }

        [JsonIgnore]
        public virtual ICollection<AsistenciaEvento> AsistenciaEventos { get; set; }

        [JsonIgnore]
        public virtual ICollection<Reserva> Reservas { get; set; }
    }
}