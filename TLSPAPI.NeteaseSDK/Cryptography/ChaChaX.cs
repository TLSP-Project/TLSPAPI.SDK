

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace TLSPAPI.NeteaseSDK.Cryptography
{
    public class ChaChaX : ChaCha7539Engine
    {
        public ChaChaX(byte[] key ,byte[] iv ,int rounds, bool forEncryption)
            : base()
        {
            this.rounds = rounds;
            Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        }

        public override string AlgorithmName
        {
            get { return "ChaCha" + rounds; }
        }
    }

}