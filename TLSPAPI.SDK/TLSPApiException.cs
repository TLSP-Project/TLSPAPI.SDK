using System;
using System.Collections.Generic;
using System.Text;
using TLSPAPI.Models;

namespace TLSPAPI.SDK
{
    public class TLSPApiException : Exception
    {
        public string Code { get; set; }

        public TLSPApiException(string code ,string msg):base(msg)
        {
            Code= code;
        }
    }
}
