using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Danchi.Models;

namespace Danchi.Utils
{
    public static class SessionHelper
    {
        public static string UserName
        {
            get => HttpContext.Current.Session["Username"] as string;
            set => HttpContext.Current.Session["Username"] = value;
        }

        public static string NombreCompleto
        {
            get => HttpContext.Current.Session["NombreCompleto"] as string;
            set => HttpContext.Current.Session["NombreCompleto"] = value;
        }

        public static string Rol
        {
            get => HttpContext.Current.Session["Rol"] as string;
            set => HttpContext.Current.Session["Rol"] = value;
        }

        public static int? UserId
        {
            get => (int?)HttpContext.Current.Session["UserId"];
            set => HttpContext.Current.Session["UserId"] = value;
        }
    }
}