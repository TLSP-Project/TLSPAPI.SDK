

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using TLSPAPI.NeteaseSDK.Models;

namespace TLSPAPI.NeteaseSDK
{
    /// <summary>
    /// 网易登录API实现
    /// </summary>
    public class MpayApiClient : IDisposable
    {
        private HttpClient client = new HttpClient() { BaseAddress = new Uri("https://service.mkey.163.com") };

        private bool disposed = false;

        private static readonly JsonSerializerOptions serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);


        /// <summary>
        /// 提交给服务器的游戏版本
        /// </summary>
        public string GameVersion { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="neteaseVersion">网易盒子版本例如：1.9.3.4963</param>
        public MpayApiClient(string gameVersion = "1.9.3.4963")
        {
            GameVersion = gameVersion;
        }

        /// <summary>
        /// 提交一些硬件信息，生成一对硬件ID和密钥供登录使用
        /// </summary>
        /// <param name="deviceName">设备名</param>
        /// <param name="macAddress">mac地址</param>
        /// <param name="udid">硬件码</param>
        /// <param name="uniqueID">uniqueID</param>
        /// <returns></returns>
        /// <exception cref="MpayApiException">调用失败会抛出这个异常</exception>
        public async Task<MpayDevice> GetMpayDeviceAsync(string deviceName ,string macAddress ,string udid ,string uniqueID)
        {

            var requestParameters = getPublicFormParameters();

            requestParameters.Add("brand", "Microsoft");
            requestParameters.Add("device_model", "pc_mode");
            
            requestParameters.Add("device_type", "Computer");
            requestParameters.Add("init_urs_device", "0");
            requestParameters.Add("resolution", "1920*1080");
            requestParameters.Add("system_name", "windows");
            requestParameters.Add("system_version", "10");
            requestParameters.Add("udid", udid);
            requestParameters.Add("unique_id", uniqueID);
            requestParameters.Add("device_name", deviceName);
            requestParameters.Add("mac", macAddress);



            var content = new FormUrlEncodedContent(requestParameters);

            var response =  await client.PostAsync("/mpay/games/aecfrxodyqaaaajp-g-x19/devices", content);

            var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

         
            try
            {
               return doc.RootElement.GetProperty("device").Deserialize<MpayDevice>(serializerOptions);
            }
            catch(KeyNotFoundException)
            {
                var code = doc.RootElement.GetProperty("code").GetInt32();
                var reason = doc.RootElement.GetProperty("reason").GetString();
                throw new MpayApiException($"GetMpayDeviceErr Code{code} Reason{reason}");
            }


        }


        /// <summary>
        /// 通过MpayDevice信息和用户名密码登录
        /// </summary>
        /// <param name="username">用户名</param>
        /// <param name="password">密码</param>
        /// <param name="uniqueID">uniqueID</param>
        /// <param name="device">MpayDevice</param>
        /// <returns></returns>
        /// <exception cref="MpayApiException">调用失败会抛出这个异常</exception>
        public async Task<MpayUser> LoginAsync(string username ,string password,string uniqueID ,MpayDevice device)
        {

            var requestParameters = getPublicFormParameters();


            var md5 = new MD5CryptoServiceProvider();
            var passwordHash = BitConverter.ToString(md5.ComputeHash(Encoding.ASCII.GetBytes(password))).Replace("-", string.Empty).ToLower();
            var parmas = "{\"password\":\"" + passwordHash + "\",\"unique_id\":\"" + uniqueID + "\",\"username\":\"" + username + "\"}";
            var parmasbuff = Encoding.ASCII.GetBytes(parmas);
            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.KeySize = 128;
                aes.Key = hexToBytes(device.Key);
                aes.Padding = PaddingMode.PKCS7;
                aes.BlockSize = 128;
                using (var cyptor = aes.CreateEncryptor())
                    requestParameters.Add("params", BitConverter.ToString(cyptor.TransformFinalBlock(parmasbuff, 0, parmasbuff.Length)).Replace("-", string.Empty).ToLower());
            }

            requestParameters.Add("un", Convert.ToBase64String(Encoding.ASCII.GetBytes(username)));
            requestParameters.Add("opt_fields", "nickname,avatar,realname_status,mobile_bind_status");
            requestParameters.Add("mcount_transaction_id", Guid.NewGuid().ToString("D") + "-2");

            var content = new FormUrlEncodedContent(requestParameters);

            var response = await client.PostAsync($"/mpay/games/aecfrxodyqaaaajp-g-x19/devices/{device.Id}/users", content);

            var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());


            try
            {
                return doc.RootElement.GetProperty("user").Deserialize<MpayUser>(serializerOptions);
            }
            catch (KeyNotFoundException)
            {
                var code = doc.RootElement.GetProperty("code").GetInt32();
                var reason = doc.RootElement.GetProperty("reason").GetString();
                throw new MpayApiException($"MapyLoginErr Code{code} Reason{reason}");
            }


        }

        /// <summary>
        /// 将16进制字符串转换为bytes
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        /// <exception cref="FormatException"></exception>
        private static byte[] hexToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex))
            {
                return null;
            }

            byte[] bytes = new byte[hex.Length / 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                try
                {

                    bytes[i] = byte.Parse(hex.Substring(i * 2, 2),
                    System.Globalization.NumberStyles.HexNumber);
                }
                catch (Exception e)
                {
                    throw new FormatException("hex is not a valid hex number!", e);
                }
            }
            return bytes;
        }

        private Dictionary<string, string> getPublicFormParameters()
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            parameters.Add("app_channel", "netease");
            parameters.Add("app_mode","2");
            parameters.Add("app_type", "games");
            parameters.Add("arch", "win_x32");
            parameters.Add("cv", "c3.9.0");
            parameters.Add("game_id", "aecfrxodyqaaaajp-g-x19");
            parameters.Add("gv", GameVersion);
            parameters.Add("mcount_app_key", "EEkEEXLymcNjM42yLY3Bn6AO15aGy4yq");
            parameters.Add("process_id", Process.GetCurrentProcess().Id.ToString());
            parameters.Add("updater_cv", "c1.0.0");
            parameters.Add("sv", "10");
            return parameters;
        }

        public void Dispose()
        {
            if (!disposed)
            {
                client.Dispose();
                disposed= true;
            }
        }
    }
}
