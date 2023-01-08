using System;
using System.Collections.Generic;
using System.Text;

namespace TLSPAPI.NeteaseSDK
{
    public class MpayApiException : Exception
    {

        public MpayApiException(string msg):base(msg)
        {
        }
    }
}
