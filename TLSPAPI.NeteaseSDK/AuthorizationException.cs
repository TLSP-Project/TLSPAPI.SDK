using System;
using System.Collections.Generic;
using System.Text;

namespace TLSPAPI.NeteaseSDK
{
    public class AuthorizationException : Exception
    {
        public AuthorizationException(string msg):base(msg) { }
    }
}
