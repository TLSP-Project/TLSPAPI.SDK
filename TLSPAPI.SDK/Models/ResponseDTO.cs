using System;
using System.Text.Json.Serialization;

namespace TLSPAPI.Models
{
    public class ResponseDTO
    {

        public Guid RequestId { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public ErrorDTO Error { get; set; }

        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Data { get; set; }

    }
}
