using System;
using System.ComponentModel;
using System.Net.Http;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using TLSPAPI.Models;
using System.Threading.Tasks;
using TLSPAPI.SDK;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Linq;

namespace TLSPAPI
{
    public class TLSPApiClient
    {
        private HttpClient client;

        private static readonly JsonSerializerOptions serializerOptions = new JsonSerializerOptions(JsonSerializerDefaults.Web);

        private static readonly DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);


        public string SecretId { get; set; }

        public string SecretKey { get; set; }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="secretId">密钥Id</param>
        /// <param name="secretKey">密钥</param>
        /// <param name="baseUri">服务器的地址，可以不填，默认为https://api.tlsp.io:14250</param>
        /// <exception cref="ArgumentNullException">SecretId 和 SecretKey 必须符合格式</exception>
        /// <exception cref="ArgumentException">SecretId 和 SecretKey 必须符合格式 , baseUri 必须以"https://"开头 </exception>
        public TLSPApiClient(string secretId, string secretKey, string baseUri = "https://112.192.19.205:14250/")
        {
            if (string.IsNullOrEmpty(secretId)) throw new ArgumentNullException(nameof(secretId), "SecretId 不能为空");
            if (string.IsNullOrEmpty(secretKey)) throw new ArgumentNullException(nameof(secretKey), "SecretKey 不能为空");
            if (secretId.Length != 32) throw new ArgumentException(nameof(secretId), "SecretId 格式不合法");
            if (secretKey.Length != 32) throw new ArgumentException(nameof(secretKey), "secretKey 格式不合法");
            if(!baseUri.StartsWith("https://")) throw new ArgumentException(nameof(baseUri), "请使用https协议");
            SecretId = secretId;
            SecretKey = secretKey;
            var rootCA = new X509Certificate2(SDK.Properties.Resources.rootCA);
            var handler = new HttpClientHandler()
            {
                ServerCertificateCustomValidationCallback = (request, certificate, chain, sslPolicyErrors) =>
                {

                    if (sslPolicyErrors == SslPolicyErrors.None)
                    {
                        return true;
                    }

                    if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
                    {
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                        chain.ChainPolicy.ExtraStore.Add(rootCA);
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                        var isValid = chain.Build(certificate);

                        var rootCertActual = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                        isValid = isValid && rootCertActual.RawData.SequenceEqual(rootCA.RawData);

                        return isValid;
                    };
                    return false;
                }
            };

            client = new HttpClient(handler) { BaseAddress = new Uri(baseUri) };

        }



        /// <summary>
        /// 生成进服验证数据
        /// </summary>
        /// <param name="gameVersion">游戏版本</param>
        /// <param name="gameId">服务器Id</param>
        /// <param name="serverId">游戏客户端生成的serverId</param>
        /// <param name="gameModsInfo">游戏Mod信息</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">参数有null</exception>
        /// <exception cref="TLSPApiException">TLSPApi执行失败，服务器返回了错误</exception>
        public async Task<byte[]> MakeAuthorizationBodyAsync(string gameVersion, ulong gameId, string serverId, IEnumerable<ModInfoDTO> gameModsInfo)
        {
            if (gameId == default)
                throw new ArgumentNullException(nameof(gameId), "服务器Id不能为0");
            if (string.IsNullOrEmpty(gameVersion))
                throw new ArgumentNullException(nameof(gameVersion), "游戏版本不能为空");
            if (gameModsInfo == default)
                throw new ArgumentNullException(nameof(gameModsInfo), "游戏Mod信息不能为空");
            if (string.IsNullOrEmpty(serverId))
                throw new ArgumentNullException(nameof(serverId), "serverId参数不能为空");


            var response = await PostAsync("MakeAuthorizationBody", "/v1/makeauthorizationbody", new
            {
                GameVersion = gameVersion,
                GameId = gameId,
                ServerId = serverId,
                GameModsInfo = gameModsInfo
            });

            if (response.Error != null)
            {
                throw new TLSPApiException(response.Error.Code, response.Error.Message);
            }
            return Convert.FromBase64String(response.Data);
        }









        /// <summary>
        /// Http解密Api
        /// </summary>
        /// <param name="needDecrypt">需要解密的数据字节数组</param>
        /// <returns>解密后的数据</returns>
        /// <exception cref="ArgumentNullException">需要解密的数据不能为Null</exception>
        /// <exception cref="TLSPApiException">TLSPApi执行失败，服务器返回了错误</exception>
        public async Task<string> HttpDecryptAsync(byte[] needDecrypt)
        {
            if (needDecrypt == default)
                throw new ArgumentNullException(nameof(needDecrypt), "需要解密的数据不能为Null");

            var response = await PostAsync("HttpDecrypt", "/v1/httpdecrypt", new
            {
                NeedDecrypt = Convert.ToBase64String(needDecrypt)
            });

            if (response.Error != null)
            {
                throw new TLSPApiException(response.Error.Code, response.Error.Message);
            }
            return response.Data;
        }

        /// <summary>
        /// Http加密Api
        /// </summary>
        /// <param name="needEncrypt">需要加密的数据文本</param>
        /// <returns>加密后的数据</returns>
        /// <exception cref="ArgumentNullException">需要加密的文本不能为空</exception>
        /// <exception cref="TLSPApiException">TLSPApi执行失败，服务器返回了错误</exception>
        public async Task<byte[]> HttpEncryptAsync(string needEncrypt)
        {
            if (string.IsNullOrEmpty(needEncrypt))
                throw new ArgumentNullException(nameof(needEncrypt), "需要加密的文本不能为空");

            var response = await PostAsync("HttpEncrypt", "/v1/httpencrypt", new
            {
                NeedEncrypt = needEncrypt
            });
            if (response.Error != null)
            {
                throw new TLSPApiException(response.Error.Code, response.Error.Message);
            }
            return Convert.FromBase64String(response.Data);
        }

        /// <summary>
        /// 向TLSPApi发送Post请求
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="path">请求路径</param>
        /// <param name="action">请求方法名称</param>
        /// <param name="request">请求参数实体</param>
        /// <returns>TLSPAPI返回的响应数据</returns>
        public async Task<ResponseDTO> PostAsync<T>(string action, string path, T request)
        {
            var body = JsonSerializer.Serialize(request, serializerOptions);
            var content = new StringContent(body, Encoding.UTF8, "application/json");
            var timeStamp = ((int)DateTime.UtcNow.Subtract(unixEpoch).TotalSeconds).ToString();
            var hashedBody = BytesToHex(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(body)));



            var stringToSign = action + "&" + timeStamp + "&" + hashedBody;

            var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(SecretKey));

            var sign = BytesToHex(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

            content.Headers.Add("X-TLSP-SecretID", SecretId);
            content.Headers.Add("X-TLSP-Sign", sign);
            content.Headers.Add("X-TLSP-Timestamp", timeStamp);
            content.Headers.Add("X-TLSP-Action", action);


            var response = await client.PostAsync(path, content);

            return JsonSerializer.Deserialize<ResponseDTO>(await response.Content.ReadAsStringAsync(), serializerOptions);
        }


        /// <summary>
        /// 将bytes转换为HEX字符串
        /// </summary>
        /// <param name="bytes"></param>
        /// <param name="toUpper">是否大写</param>
        /// <returns></returns>
        public static string BytesToHex(byte[] bytes, bool toUpper = false)
        {
            StringBuilder ret = new StringBuilder();
            foreach (byte b in bytes)
            {
                ret.AppendFormat(toUpper ? "{0:X2}" : "{0:x2}", b);
            }
            return ret.ToString();
        }

    }
}
