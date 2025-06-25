using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Data.Entity.Infrastructure.Annotations;
using System.Linq;
using System.Web;
using Danchi.Models;

namespace Danchi.Context
{
    public class DanchiDBContext : DbContext
    {
        public DanchiDBContext() : base("name=DanchiDB")
        {
        }

        public DbSet<Usuario> Usuarios { get; set; }
        public DbSet<Rol> Rol { get; set; }
        public DbSet<Torre> Torres { get; set; }
        public DbSet<Apto> Aptos { get; set; }
        public DbSet<Propietario> Propietarios { get; set; }
        public DbSet<TiposDocumento> TiposDocumento { get; set; }
        public DbSet<Evento> Eventos { get; set; }
        public DbSet<Aviso> Avisos { get; set; }
        public DbSet<Mensaje> Mensajes { get; set; }
        public DbSet<AsistenciaEvento> AsistenciaEventos { get; set; }
        public DbSet<Reserva> Reservas { get; set; }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            #region Usuarios

            modelBuilder.Entity<Usuario>()
                .ToTable("Usuarios");

            modelBuilder.Entity<Usuario>()
                .HasKey(u => u.IdUsuario);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.Nombres)
                .HasColumnName("Nombres")
                .HasMaxLength(100);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.Apellidos)
                 .HasColumnName("Apellidos")
                .HasMaxLength(100);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.Correo)
                .HasMaxLength(100);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.Telefono)
                 .HasColumnName("Telefono")
                .HasMaxLength(10);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.Contrasena)
                 .HasColumnName("Contrasena")
                .HasMaxLength(50);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.HashKey)
                .HasColumnType("binary")
                .HasMaxLength(32);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.HashIV)
                .HasColumnType("binary")
                .HasMaxLength(16);

            modelBuilder.Entity<Usuario>()
                .Property(u => u.FechaCreacion)
                .HasColumnName("FechaCreacion")
                .IsRequired();

            modelBuilder.Entity<Usuario>()
                .Property(u => u.UsuarioCreacion)
                .HasColumnName("UsuarioCreacion")
                .IsRequired();

            modelBuilder.Entity<Usuario>()
                .Property(u => u.FechaModificacion)
                .HasColumnName("FechaModificacion")
                .IsOptional();

            modelBuilder.Entity<Usuario>()
                .Property(u => u.UsuarioModificacion)
                .HasColumnName("UsuarioModificacion")
                .IsOptional();

            modelBuilder.Entity<Usuario>()
                .HasRequired(u => u.Rol)
                .WithMany(r => r.Usuarios)
                .HasForeignKey(u => u.IdRol);

            #endregion

            #region Rol

            modelBuilder.Entity<Rol>()
               .ToTable("Roles");

            modelBuilder.Entity<Rol>()
                .HasKey(u => u.IdRol);

            modelBuilder.Entity<Rol>()
               .Property(u => u.DescripcionRol)
               .HasColumnName("DescripcionRol")
               .IsRequired();

            modelBuilder.Entity<Rol>()
               .Property(u => u.FechaCreacion)
               .HasColumnName("FechaCreacion")
               .IsRequired();

            modelBuilder.Entity<Rol>()
                .Property(u => u.UsuarioCreacion)
                .HasColumnName("UsuarioCreacion")
                .IsRequired();

            modelBuilder.Entity<Rol>()
                .Property(u => u.FechaModificacion)
                .HasColumnName("FechaModificacion")
                .IsOptional();

            modelBuilder.Entity<Rol>()
                .Property(u => u.UsuarioModificacion)
                .HasColumnName("UsuarioModificacion")
                .IsOptional();

            #endregion

            #region Torres

            modelBuilder.Entity<Torre>()
               .ToTable("Torres");

            modelBuilder.Entity<Torre>()
                .HasKey(u => u.IdTorre);

            modelBuilder.Entity<Torre>()
               .Property(u => u.NombreTorre)
               .HasColumnName("NombreTorre")
               .IsRequired();

            modelBuilder.Entity<Torre>()
               .Property(u => u.FechaCreacion)
               .HasColumnName("FechaCreacion")
               .IsRequired();

            modelBuilder.Entity<Torre>()
                .Property(u => u.UsuarioCreacion)
                .HasColumnName("UsuarioCreacion")
                .IsRequired();

            modelBuilder.Entity<Torre>()
                .Property(u => u.FechaModificacion)
                .HasColumnName("FechaModificacion")
                .IsOptional();

            modelBuilder.Entity<Torre>()
                .Property(u => u.UsuarioModificacion)
                .HasColumnName("UsuarioModificacion")
                .IsOptional();

            #endregion

            #region Aptos

            modelBuilder.Entity<Apto>()
               .ToTable("Aptos");

            modelBuilder.Entity<Apto>()
                .HasKey(u => u.IdApto);

            modelBuilder.Entity<Apto>()
               .Property(u => u.NombreApto)
               .HasColumnName("NombreApto")
               .IsRequired();

            modelBuilder.Entity<Apto>()
              .Property(u => u.IdTorre)
              .HasColumnName("IdTorre")
              .IsRequired();

            modelBuilder.Entity<Apto>()
               .Property(u => u.FechaCreacion)
               .HasColumnName("FechaCreacion")
               .IsRequired();

            modelBuilder.Entity<Apto>()
                .Property(u => u.UsuarioCreacion)
                .HasColumnName("UsuarioCreacion")
                .IsRequired();

            modelBuilder.Entity<Apto>()
                .Property(u => u.FechaModificacion)
                .HasColumnName("FechaModificacion")
                .IsOptional();

            modelBuilder.Entity<Apto>()
                .Property(u => u.UsuarioModificacion)
                .HasColumnName("UsuarioModificacion")
                .IsOptional();

            modelBuilder.Entity<Apto>()
               .HasRequired(u => u.Torre)
               .WithMany(r => r.Aptos)
               .HasForeignKey(u => u.IdTorre);

            #endregion

            #region Propietarios

            modelBuilder.Entity<Propietario>()
                .ToTable("Propietarios")
                .HasKey(p => p.IdPropietario);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.NumeroDocumento)
                .IsRequired()
                .HasMaxLength(11);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.Apellidos)
                .IsRequired()
                .HasMaxLength(50);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.Nombres)
                .IsRequired()
                .HasMaxLength(50);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.Correo)
                .IsRequired()
                .HasMaxLength(50);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.Telefono)
                .IsOptional()
                .HasMaxLength(10);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.Celular)
                .IsOptional()
                .HasMaxLength(10);

            modelBuilder.Entity<Propietario>()
                .Property(p => p.FechaCreacion)
                .IsRequired();

            modelBuilder.Entity<Propietario>()
                .Property(p => p.UsuarioCreacion)
                .IsRequired();

            modelBuilder.Entity<Propietario>()
                .Property(p => p.FechaModificacion)
                .IsOptional();

            modelBuilder.Entity<Propietario>()
                .Property(p => p.UsuarioModificacion)
                .IsOptional();

            modelBuilder.Entity<Propietario>()
                .HasRequired(p => p.Apto)
                .WithMany(a => a.Propietarios)
                .HasForeignKey(p => p.IdApto)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<Propietario>()
                .HasRequired(p => p.TiposDocumento)
                .WithMany(td => td.Propietarios)
                .HasForeignKey(p => p.IdTipoDocumento)
                .WillCascadeOnDelete(false);

            #endregion

            #region Tipos de Documento

            modelBuilder.Entity<TiposDocumento>()
                .ToTable("TiposDocumento")
                .HasKey(td => td.IdTipoDocumento);

            modelBuilder.Entity<TiposDocumento>()
                .Property(td => td.NombreTipoDocumento)
                .IsRequired()
                .HasMaxLength(50);

            modelBuilder.Entity<TiposDocumento>()
                .Property(td => td.Abreviatura)
                .IsRequired()
                .HasMaxLength(4);

            #endregion

            #region Eventos

            modelBuilder.Entity<Evento>()
                .ToTable("Eventos")
                .HasKey(e => e.IdEvento);

            modelBuilder.Entity<Evento>()
                .Property(e => e.Titulo)
                .IsRequired()
                .HasMaxLength(150);

            modelBuilder.Entity<Evento>()
                .Property(e => e.Descripcion)
                .IsRequired()
                .IsMaxLength();

            modelBuilder.Entity<Evento>()
                .Property(e => e.FechaEvento)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.HoraInicio)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.HoraFin)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.Lugar)
                .IsRequired()
                .HasMaxLength(150);

            modelBuilder.Entity<Evento>()
                .Property(e => e.Estado)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.FechaCreacion)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.UsuarioCreacion)
                .IsRequired();

            modelBuilder.Entity<Evento>()
                .Property(e => e.FechaModificacion)
                .IsOptional();

            modelBuilder.Entity<Evento>()
                .Property(e => e.UsuarioModificacion)
                .IsOptional();

            #endregion

            #region Avisos

            modelBuilder.Entity<Aviso>()
                .ToTable("Avisos")
                .HasKey(a => a.IdAviso);

            modelBuilder.Entity<Aviso>()
                .Property(a => a.Titulo)
                .IsRequired()
                .HasMaxLength(150);

            modelBuilder.Entity<Aviso>()
                .Property(a => a.Descripcion)
                .IsRequired()
                .IsMaxLength();

            modelBuilder.Entity<Aviso>()
                .Property(a => a.Estado)
                .IsRequired();

            modelBuilder.Entity<Aviso>()
                .Property(a => a.FechaCreacion)
                .IsRequired();

            modelBuilder.Entity<Aviso>()
                .Property(a => a.UsuarioCreacion)
                .IsRequired();

            modelBuilder.Entity<Aviso>()
                .Property(a => a.FechaModificacion)
                .IsOptional();

            modelBuilder.Entity<Aviso>()
                .Property(a => a.UsuarioModificacion)
                .IsOptional();

            #endregion

            #region Mensajes 

            modelBuilder.Entity<Mensaje>()
                .ToTable("Mensajes")
                .HasKey(m => m.IdMensaje);

            modelBuilder.Entity<Mensaje>()
                .Property(m => m.Asunto)
                .IsRequired()
                .HasMaxLength(100);

            modelBuilder.Entity<Mensaje>()
                .Property(m => m.Descripcion)
                .IsRequired()
                .IsMaxLength();

            modelBuilder.Entity<Mensaje>()
                .Property(m => m.FechaEnvio)
                .IsRequired();

            modelBuilder.Entity<Mensaje>()
                .Property(m => m.ArchivoAdjunto)
                .IsOptional()
                .IsMaxLength();

            modelBuilder.Entity<Mensaje>()
               .Property(m => m.IdEmisor)
               .IsRequired();

            modelBuilder.Entity<Mensaje>()
              .Property(m => m.IdReceptor)
              .IsRequired();

            modelBuilder.Entity<Mensaje>()
                        .HasOptional(m => m.MensajePadre)
                        .WithMany(m => m.Respuestas)
                        .HasForeignKey(m => m.MensajePadreId)
                        .WillCascadeOnDelete(false);

            modelBuilder.Entity<Mensaje>()
               .HasRequired(m => m.Emisor)
               .WithMany(u => u.MensajesEnviados)
               .HasForeignKey(m => m.IdEmisor)
               .WillCascadeOnDelete(false);

            modelBuilder.Entity<Mensaje>()
                .HasRequired(m => m.Receptor)
                .WithMany(u => u.MensajesRecibidos)
                .HasForeignKey(m => m.IdReceptor)
                .WillCascadeOnDelete(false);


            #endregion

            #region AsistenciaEventos

            modelBuilder.Entity<AsistenciaEvento>()
                .ToTable("AsistenciaEventos");

            modelBuilder.Entity<AsistenciaEvento>()
                .HasKey(a => a.IdAsistencia);

            modelBuilder.Entity<AsistenciaEvento>()
                .Property(a => a.Confirmado)
                .IsRequired();

            modelBuilder.Entity<AsistenciaEvento>()
                .Property(a => a.FechaConfirmacion)
                .IsRequired();

            modelBuilder.Entity<AsistenciaEvento>()
                .HasRequired(a => a.Usuario)
                .WithMany(u => u.AsistenciaEventos)
                .HasForeignKey(a => a.IdUsuario)
                .WillCascadeOnDelete(false);

            modelBuilder.Entity<AsistenciaEvento>()
                .HasRequired(a => a.Evento)
                .WithMany(e => e.AsistenciaEventos)
                .HasForeignKey(a => a.IdEvento)
                .WillCascadeOnDelete(false);

            #endregion

            #region Reservas

            modelBuilder.Entity<Reserva>()
                .ToTable("Reservas")
                .HasKey(r => r.IdReserva);

            modelBuilder.Entity<Reserva>()
                .Property(r => r.Zona)
                .IsRequired()
                .HasMaxLength(100);

            modelBuilder.Entity<Reserva>()
                .Property(r => r.FechaReserva)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.HoraInicio)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.HoraFin)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.NumInvitados)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.FechaCreacion)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.UsuarioCreacion)
                .IsRequired();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.FechaModificacion)
                .IsOptional();

            modelBuilder.Entity<Reserva>()
                .Property(r => r.UsuarioModificacion)
                .IsOptional();

            modelBuilder.Entity<Reserva>()
                .HasRequired(r => r.Usuario)
                .WithMany(u => u.Reservas)
                .HasForeignKey(r => r.IdUsuario)
                .WillCascadeOnDelete(false);

            #endregion

            base.OnModelCreating(modelBuilder);
        }
    }
}