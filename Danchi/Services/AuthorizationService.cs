using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Danchi.Context;
using Danchi.Models;
using Danchi.Security;
using Danchi.Utils;

namespace Danchi.Services
{
    public class AuthorizationService : IAuthorizationService
    {
        private readonly DanchiDBContext db = new DanchiDBContext();
        private readonly IPasswordEncripter _passordEncripter = new PasswordEncripter();

        public AuthResults Auth(string user, string password, out Usuario usuario)
        {
            usuario = db.Usuarios.Where(x => x.Correo.Equals(user)).FirstOrDefault();

            if (usuario == null)
                return AuthResults.NotExists;

            password = _passordEncripter.Encript(password, new List<byte[]>()
                .AddHash(usuario.HashKey)
                .AddHash(usuario.HashIV)
                );
            if (password != usuario.Contrasena)
                return AuthResults.PasswordNotMatch;

            return AuthResults.Success;
        }
    }
}