

using System.Text.Json;
using System.Text.RegularExpressions;
using TLSPAPI;
using TLSPAPI.Models;
using TLSPAPI.NeteaseSDK;




//创建一个用来调用TLSPApi的实例

var tlspApi = new TLSPApiClient("ctFKN7bcyrWaJRGKVvpyzpUaZJEvCbW5", "BnzfrNzBKDxgWqaV27HMS5XCPGkq6NtW", "https://112.192.19.205:14250/");
//var tlspApi = new TLSPApiClient("Usy47xMn92TnQhVvNtg66hqH2A4cDqU7", "rn9S474PWEckPV2taNTzMaKpXTuCmjuJ", "http://localhost:5215");



//网易的一些接口需要硬件信息，这里随机生成了一些
var deviceName = "DESKTOP-" + Guid.NewGuid().ToString("N").Substring(0, 7).ToUpperInvariant();
var macAddress = string.Format("{0}-{1}-{2}-{3}-{4}-{5}", Regex.Split(Guid.NewGuid().ToString("N").ToUpperInvariant(), "(?<=\\G.{2})"));
var udid = Guid.NewGuid().ToString("N");
var uniqueId = Guid.NewGuid().ToString("N");








//创建一个调用MpayApi的实例
var mpayApi = new MpayApiClient("1.9.3.4963");

//通过上传硬件信息到MpayApi，可以获得一个MpayDevice包含硬件ID和AES密钥，登录时会用到
var mpayDevice = await mpayApi.GetMpayDeviceAsync(deviceName, macAddress, udid, uniqueId);

//通过MpayApi登录网易账户
var mpayUser = await mpayApi.LoginAsync("tvdc211495@163.com", "370110", uniqueId, mpayDevice);



//从mpay返回的token等数据构建sauth
var sauth = "{\"gameid\":\"x19\",\"login_channel\":\"netease\",\"app_channel\":\"netease\",\"platform\":\"pc\",\"sdkuid\":\"" + mpayUser.Id + "\",\"sessionid\":\"" + mpayUser.Token + "\",\"sdk_version\":\"3.9.0\",\"udid\":\"" + udid + "\",\"deviceid\":\"" + mpayDevice.Id + "\",\"aim_info\":\"{\\\"aim\\\":\\\"" + mpayUser.PcExtInfo.SrcClientIp + "\\\",\\\"country\\\":\\\"CN\\\",\\\"tz\\\":\\\"+0800\\\",\\\"tzid\\\":\\\"\\\"}\",\"client_login_sn\":\"" + Guid.NewGuid().ToString("N").ToUpperInvariant() + "\",\"gas_token\":\"\",\"source_platform\":\"pc\",\"ip\":\"" + Guid.NewGuid().ToString("N").ToUpperInvariant() + "\"}";





//创建一个调用网易盒子Api的HttpClient
var neteaseMcApiClient = new HttpClient() { BaseAddress = new Uri("https://x19obtcore.nie.netease.com:8443") };


//构造loginOtp请求参数
var loginOtpRequetStr = JsonSerializer.Serialize(new
{
    sauth_json = sauth
});

//执行LoginOtp请求
var loginOtpResponse = await (await neteaseMcApiClient.PostAsync("/login-otp", new StringContent(loginOtpRequetStr))).Content.ReadAsStringAsync();


//从login-otp返回的数据中取出账号ID和OTPToken
var loginOtpResJson = JsonDocument.Parse(loginOtpResponse);
var otpToken = loginOtpResJson.RootElement.GetProperty("entity").GetProperty("otp_token").GetString();
var accountID = loginOtpResJson.RootElement.GetProperty("entity").GetProperty("aid").GetUInt32();




//构造authenticationOtp的请求参数
var authenticationOtpRequetStr = JsonSerializer.Serialize(new
{
    otp_token = otpToken,
    otp_pwd = string.Empty,
    aid = accountID,
    sauth_json = sauth,
    sa_data = "{\"os_name\":\"windows\",\"os_ver\":\"Microsoft Windows 10\",\"mac_addr\":\"" + macAddress.Replace("-", "") + "\",\"udid\":\"" + udid + "\",\"app_ver\":\"0.0.0.0\",\"sdk_ver\":\"\",\"network\":\"\",\"disk\":\"012345678\",\"is64bit\":\"1\",\"video_card1\":\"NVIDIA GeForce GTX 1060\",\"video_card2\":\"\",\"video_card3\":\"\",\"video_card4\":\"\",\"launcher_type\":\"PC_java\",\"pay_channel\":\"netease\"}",
    version = new
    {
        version = "1.9.3.4963",
        launcher_md5 = string.Empty,
        updater_md5 = string.Empty
    }
});

//由于AuthenticationOtp接口数据加密，所以需要调用tlspapi的HttpEncrypt接口加密请求参数
var enAuthenticationOtpRequet = await tlspApi.HttpEncryptAsync(authenticationOtpRequetStr);

//执行AuthenticationOtp请求
var authOtpResponseEn = await (await neteaseMcApiClient.PostAsync("/authentication-otp", new ByteArrayContent(enAuthenticationOtpRequet))).Content.ReadAsByteArrayAsync();

//由于AuthenticationOtp接口数据加密，所以需要调用tlspapi的HttpDecrypt接口解密响应数据
var authOtpResponseStr = await tlspApi.HttpDecryptAsync(authOtpResponseEn);


//取出认证成功后服务器返回的token和userId
var authOtpResJson = JsonDocument.Parse(authOtpResponseStr);
var token = authOtpResJson.RootElement.GetProperty("entity").GetProperty("token").GetString();
var userId = uint.Parse(authOtpResJson.RootElement.GetProperty("entity").GetProperty("entity_id").GetString());


//连接进服验证服务器，返回一个authClient实例用来后续的进服认证
var authClient =  GameAuthClient.MakeAuthentication("45.253.165.190", 10400, userId, token);

//花雨庭的服务器Id
var gameId = 77114517833647104UL;
//花雨庭的服务器版本是1.12.2
var gameVersion = "1.12.2";
//游戏客户端生成的serverId，这里随机一个试试
var serverId = "517f47a95e6f5ab2497c03a689bc4bae";


//花雨庭白端mod信息，用来进服验证
var modInfos = new List<ModInfoDTO>();
modInfos.Add(new ModInfoDTO { FileName = "4620608844487847104@3@0.jar", Md5 = "B260855E8FDEAE184FEEA0F6683F5409" });
modInfos.Add(new ModInfoDTO { FileName = "4621632218832071536@3@0.jar", Md5 = "19324A1CB2BBE94CF422E225B14B6BFF" });
modInfos.Add(new ModInfoDTO { FileName = "4624104029891423116@3@0.jar", Md5 = "B7FE765E2EF1601A6B62D057C3539388" });
modInfos.Add(new ModInfoDTO { FileName = "4620702976810361335@3@0.jar", Md5 = "6A06C67C0C99EC30995BA040A454D5D4" });
modInfos.Add(new ModInfoDTO { FileName = "4640208094372507127@3@0.jar", Md5 = "72167D680F4ED888028691046F052510" });
modInfos.Add(new ModInfoDTO { FileName = "4633394671597683929@3@0.jar", Md5 = "517F47A95E6F5AB2497C03A689BC4BAE" });
modInfos.Add(new ModInfoDTO { FileName = "4652953849815032763@3@0.jar", Md5 = "762BC1A68596BD039949A71AB50331B3" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587184941527@2@11.jar", Md5 = "A0FC91B12299557DC4F481A82A8AF270" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587192428534@2@11.jar", Md5 = "0A5B39E1EE4FAA102CD7CC3D812DF792" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587214212330@2@11.jar", Md5 = "22334D3869D513A52276C3A128FCC333" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587221689727@2@11.jar", Md5 = "BCE7EA7111808CDA4491EA06FAB65219" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587207122571@2@11.jar", Md5 = "6712A80DF20ACA7309162DEA80688CBE" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587199606534@2@11.jar", Md5 = "969583C7B6ED68C4D6A18F141D3AC10B" });
modInfos.Add(new ModInfoDTO { FileName = "4620273834210283309@3@0.jar", Md5 = "31E33BDA2DA5782E213C261C4F7F67C6" });
modInfos.Add(new ModInfoDTO { FileName = "4620273834395780067@3@0.jar", Md5 = "8F689D988D3E12BDF483122217AB07FF" });
modInfos.Add(new ModInfoDTO { FileName = "4620273834451558259@3@0.jar", Md5 = "16F1B443D0731C9A28C39DEF3EECCB87" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587168260432@2@11.jar", Md5 = "694248028B74151981BBB97C1E565843" });
modInfos.Add(new ModInfoDTO { FileName = "4660517239875585007@3@0.jar", Md5 = "1B1AE0543E4B9B8CD3998DA6BD05DF97" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587238167877@2@11.jar", Md5 = "196399464DBD7BF3D7003AB9AD99AFF3" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587176119368@2@11.jar", Md5 = "54E561E441192CF009803AE95873C5D0" });
modInfos.Add(new ModInfoDTO { FileName = "4660250587229169237@2@11.jar", Md5 = "999647C001E6A18F566557A7C6B5CD7A" });





//通过TLSP Api生成进服认证数据
var authorizationBody = await tlspApi.MakeAuthorizationBodyAsync(gameVersion,gameId,serverId, modInfos);

//发送进服认证数据
await authClient.SendAuthorizationBody(authorizationBody);

//认证成功
Console.WriteLine("进服成功");

//尝试第二次认证
await authClient.SendAuthorizationBody(authorizationBody);

//认证成功
Console.WriteLine("重连成功");
Console.ReadLine();



