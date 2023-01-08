using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace TLSPAPI.NeteaseSDK.Models
{
    public class MpayUser
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("avatar")]
        public string Avatar { get; set; }

        [JsonPropertyName("client_username")]
        public string ClientUsername { get; set; }

        [JsonPropertyName("display_username")]
        public string DisplayUsername { get; set; }

        [JsonPropertyName("login_channel")]
        public string LoginChannel { get; set; }

        [JsonPropertyName("login_type")]
        public int LoginType { get; set; }

        [JsonPropertyName("mobile_bind_status")]
        public int MobileBindStatus { get; set; }

        [JsonPropertyName("need_aas")]
        public bool NeedAas { get; set; }

        [JsonPropertyName("need_mask")]
        public bool NeedMask { get; set; }

        [JsonPropertyName("nickname")]
        public string NickName { get; set; }

        [JsonPropertyName("pc_ext_info")]
        public PcExtInfoEntity PcExtInfo { get; set; }

        [Serializable]
        public class PcExtInfoEntity
        {
            [JsonPropertyName("extra_unisdk_data")]
            public string ExtraUnisdkData { get; set; }

            [JsonPropertyName("from_game_id")]
            public string FromGameId { get; set; }

            [JsonPropertyName("src_app_channel")]
            public string SrcAppChannel { get; set; }

            [JsonPropertyName("src_client_ip")]
            public string SrcClientIp { get; set; }

            [JsonPropertyName("src_client_type")]
            public int SrcClientType { get; set; }

            [JsonPropertyName("src_jf_game_id")]
            public string SrcJfGameId { get; set; }

            [JsonPropertyName("src_pay_channel")]
            public string SrcPayChannel { get; set; }

            [JsonPropertyName("src_sdk_version")]
            public string SrcSdkVersion { get; set; }

            [JsonPropertyName("src_udid")]
            public string SrcUdid { get; set; }
        }
        [JsonPropertyName("realname_status")]
        public int RealnameStatus { get; set; }

        [JsonPropertyName("realname_verify_status")]
        public int RealnameVerifyStatus { get; set; }


        [JsonPropertyName("ext_access_token")]
        public string ExtAccessToken { get; set; }

        [JsonPropertyName("token")]
        public string Token { get; set; }
    }
}
