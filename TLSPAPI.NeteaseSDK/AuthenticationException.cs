using System;
using System.Collections.Generic;
using System.Text;

namespace TLSPAPI.NeteaseSDK
{
    public class AuthenticationException : Exception
    {

        public AuthenticationException(string msg):base(msg) { }
    }
}
