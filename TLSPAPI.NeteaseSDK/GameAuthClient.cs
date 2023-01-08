
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TLSPAPI.NeteaseSDK.Cryptography;
using TLSPAPI.NeteaseSDK.Extensions;

namespace TLSPAPI.NeteaseSDK
{

    /// <summary>
    /// 进服验证握手以及发包实现
    /// </summary>
    public class GameAuthClient : IDisposable
    {


        private static readonly byte[] tokenKey = { 0xAC, 0x24, 0x9C, 0x69, 0xC7, 0x2C, 0xB3, 0xB4, 0x4E, 0xC0, 0xCC, 0x6C, 0x54, 0x3A, 0x81, 0x95 };

        private static readonly byte[] chachaIV = { 0x31, 0x36, 0x33, 0x20, 0x4E, 0x65, 0x74, 0x45, 0x61, 0x73, 0x65, 0x0A };

        private static readonly Skip32 skip32Codec = new Skip32(Encoding.UTF8.GetBytes("SaintSteve"));

        private CRC32 crc32 = new CRC32();

        private ChaChaX chachaEn;

        private ChaChaX chachaDe;

        private TcpClient client;

        private BinaryReader reader;

        private BinaryWriter writer;

        private NetworkStream stream;

        private BlockingCollection<(TaskCompletionSource<object>,Func<Task>)> taskQueue = new BlockingCollection<(TaskCompletionSource<object>, Func<Task>)>();
      

        private bool reConnect = false;

        private bool disposed = false;

        private Task worker;

        private Task reciveWorker;

        private Dictionary<byte, Action<byte[]>> packetHandleDic = new Dictionary<byte, Action<byte[]>>();

        private Semaphore authSemaphore = new Semaphore(0, 1);

        private Semaphore reconnetSemaphore = new Semaphore(0, 1);

        private byte lastAuthState = 0XFF;

        private byte lastReconnetState = 0xFF;

        private CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

        public bool Connected { get => client.Connected; }


        private GameAuthClient()
        {

            packetHandleDic.Add(9, data =>
            {
                lastAuthState = data[0];
                authSemaphore.Release(1);

            });
            //packetHandleDic.Add(5, data =>
            //{
            //    Console.WriteLine(Encoding.UTF8.GetString(data, 1, data.Length - 1));
            //});
            packetHandleDic.Add(7, data =>
            {
                lastReconnetState = data[0];
                reconnetSemaphore.Release(1);

            });
            worker = new Task(async () =>
            {
                while (true)
                {
                    cancellationTokenSource.Token.ThrowIfCancellationRequested();
                    (TaskCompletionSource<object>,Func<Task>) task;
                    if (taskQueue.TryTake(out task, TimeSpan.FromSeconds(30)))
                    {
                        if (cancellationTokenSource.Token.IsCancellationRequested)
                        {
                            task.Item1.SetCanceled();
                            cancellationTokenSource.Token.ThrowIfCancellationRequested();
                        }
                        await task.Item2();
                    }
                        
                    else
                    {
                        cancellationTokenSource.Token.ThrowIfCancellationRequested();
                        writer.Write((short)0);
                    }
                        
                }

            }, cancellationTokenSource.Token);
            reciveWorker = new Task(async () =>
            {
                while (true)
                {
                    if (cancellationTokenSource.Token.IsCancellationRequested)
                    {
                        cancellationTokenSource.Token.ThrowIfCancellationRequested();
                    }
                    var countBuffer = new byte[2];
                    var count = 0;


                    do
                    {
                        count += await stream.ReadAsync(countBuffer, count, 2 - count);

                    } while (count != 2);

                    var packetSize = BitConverter.ToUInt16(countBuffer, 0);

                    var recvBytes = reader.ReadBytes(packetSize);
                    chachaDe.ProcessBytes(recvBytes,0, recvBytes.Length, recvBytes,0);


                    var crcBytes = crc32.ComputeHash(recvBytes, 4, recvBytes.Length - 4);

                    for (int i = 0; i < 4; i++)
                    {
                        if (recvBytes[i] != crcBytes[i])
                        {
                            throw new AuthorizationException("Auth Srv CRC32 is Err");
                        }
                    }

                    if (packetHandleDic.ContainsKey(recvBytes[4]))
                    {
                        packetHandleDic[recvBytes[4]](recvBytes.Skip(8).ToArray());
                    }
                }
            }, cancellationTokenSource.Token);
        }

        private Task run(Func<Task> lambda)
        {
            var tcs = new TaskCompletionSource<object>();
            taskQueue.Add((tcs,async () =>
            {
                try
                {
                    await lambda();
                    tcs.TrySetResult(null);
                }
                catch (OperationCanceledException ex)
                {
                    tcs.TrySetCanceled(ex.CancellationToken);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }));
            return tcs.Task;
        }
        private Task run(Action lambda)
        {
            var tcs = new TaskCompletionSource<object>();
            taskQueue.Add((tcs ,() =>
            {
                try
                {
                    lambda();
                    tcs.TrySetResult(null);
                }
                catch (OperationCanceledException ex)
                {
                    tcs.TrySetCanceled(ex.CancellationToken);
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
                return Task.CompletedTask;
            }));
            return tcs.Task;
        }


        /// <summary>
        /// 通过userId与userToken跟验证服务器握手并进行身份认证
        /// </summary>
        /// <param name="authServerHost">验证服务器地址</param>
        /// <param name="authServerPort">验证服务器端口</param>
        /// <param name="userId">用户Id</param>
        /// <param name="userToken">token</param>
        /// <returns></returns>
        /// <exception cref="AuthenticationException">身份认证失败会抛出这个异常</exception>
        public static GameAuthClient MakeAuthentication(string authServerHost, int authServerPort, uint userId, string userToken)
        {
            var tcpClient = new TcpClient();

            tcpClient.Connect(authServerHost, authServerPort);

            var stream = tcpClient.GetStream();

            var writer = new BinaryWriter(stream);

            var reader = new BinaryReader(stream);

            byte[] handShakeKey = reader.ReadBytes(reader.ReadUInt16());

            byte[] encryptedToken = Encoding.ASCII.GetBytes(userToken).Xor(tokenKey);


            writer.Write((ushort)21);
            writer.Write(BitConverter.GetBytes(skip32Codec.Encrypt(userId)));
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.BlockSize = 128;
                aes.KeySize = 128;
                aes.Key = encryptedToken;
                using (var encryptor = aes.CreateEncryptor())
                {
                    writer.Write(encryptor.TransformFinalBlock(handShakeKey, 0, handShakeKey.Length));
                }
            }

            writer.Write((byte)0);
            byte[] result = reader.ReadBytes(reader.ReadUInt16());

            if (result[0] != 0)
            {
                tcpClient.Close();
                throw new AuthenticationException("身份认证失败，可能是Token或UserID错误");
            }

            var gameAuthClient = new GameAuthClient()
            {
                client = tcpClient,
                writer = writer,
                reader = reader,
                stream = stream,
                chachaEn = new ChaChaX(encryptedToken.Concat(handShakeKey).ToArray(),chachaIV,8,true),
                chachaDe = new ChaChaX(handShakeKey.Concat(encryptedToken).ToArray(),chachaIV,8,false)
            };
            gameAuthClient.reciveWorker.Start();
            gameAuthClient.worker.Start();
            return gameAuthClient;
        }


        /// <summary>
        /// 通过发送authorizationBody给验证服务器进行进服授权
        /// </summary>
        /// <param name="authorizationBody">从TLSP Api接口获得的授权数据</param>
        /// <returns></returns>
        /// <exception cref="AuthorizationException">授权失败会引发此异常</exception>
        public Task SendAuthorizationBody(byte[] authorizationBody)
        {
            if (worker.IsCompleted || worker.IsFaulted || !Connected || disposed)
                throw new AuthorizationException("认证失败！此连接已失效！请重新创建！");
            return run(() =>
            {
                if (reConnect)
                {
                    while (reconnetSemaphore.WaitOne(1)) ;
                    authSend(7);
                    if (!reconnetSemaphore.WaitOne(10_000))
                        throw new AuthorizationException($"请求重连超时！");
                    if (lastReconnetState != 0)
                        throw new AuthorizationException($"请求重连错误:{lastReconnetState}");
                }
                else
                    reConnect = true;

                while (authSemaphore.WaitOne(1)) ;
                authSend(9, authorizationBody);

                if (!authSemaphore.WaitOne(10_000))
                    throw new AuthorizationException("请求进服超时！");
                else if (lastAuthState != 0)
                    throw new AuthorizationException($"请求进服错误:{lastAuthState}");
            });
        }

        private void authSend(byte id = 8, byte[] data = null)
        {
            byte[] packetBuffer = new byte[(data?.Length ?? 0) + 8];

            packetBuffer[4] = id;
            packetBuffer[5] = 0x88;
            packetBuffer[6] = 0x88;
            packetBuffer[7] = 0x88;

            data?.CopyTo(packetBuffer, 8);

            crc32.ComputeHash(packetBuffer, 4, packetBuffer.Length - 4).CopyTo(packetBuffer, 0);
            chachaEn.ProcessBytes(packetBuffer,0, packetBuffer.Length, packetBuffer,0);
            writer.Write((ushort)packetBuffer.Length);
            writer.Write(packetBuffer);
        }

        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                cancellationTokenSource.Cancel();

                cancellationTokenSource.Dispose();

                worker.Dispose();

                reciveWorker.Dispose();

                client.Dispose();
                //chachaEn.Dispose();
                //chachaDe.Dispose();

                reconnetSemaphore.Dispose();

                authSemaphore.Dispose();
                (TaskCompletionSource<object>, Func<Task>) task;
                while(taskQueue.TryTake(out task, 100))
                    task.Item1.SetCanceled();
                taskQueue.Dispose();
            }
            GC.SuppressFinalize(this);
        }
    }

}
