using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace Danchi.Controllers
{
    public class ErrorController : Controller
    {
        public async Task<ActionResult> Unauthorized()
        {
            return View();
        }
    }
}