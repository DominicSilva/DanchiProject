using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace Danchi.Utils
{
    public static class HashHelper
    {
        public static List<byte[]> AddHash(this List<byte[]> lst, byte[] hash)
        {
            if (lst == null)
                lst = new List<byte[]>();
            lst.Add(hash);
            return lst;
        }
    }
}