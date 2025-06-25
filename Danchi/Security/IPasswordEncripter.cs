using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Danchi.Security
{
    public interface IPasswordEncripter
    {
        string Encript(string value, out List<byte[]> hashes);
        string Encript(string value, List<byte[]> hashes);
        string Decript(string value, List<byte[]> hash);
    }
}