using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Attributes.Jobs;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace dotnet_cert_perf
{
    [CoreJob]
    public class CopyWithPrivateKeyBenchmarks
    {
        private X509Certificate2 certificate;
        private RSAParameters parameters;
        private RSA rsa;

        [GlobalSetup]
        public void Initialize()
        {
            this.certificate = new X509Certificate2("cert.crt");
            this.parameters = new RSAParameters()
            {
                D = File.ReadAllBytes("d.bin"),
                DP = File.ReadAllBytes("dp.bin"),
                DQ = File.ReadAllBytes("dq.bin"),
                Exponent = File.ReadAllBytes("exponent.bin"),
                InverseQ = File.ReadAllBytes("inverseQ.bin"),
                Modulus = File.ReadAllBytes("modulus.bin"),
                P = File.ReadAllBytes("p.bin"),
                Q = File.ReadAllBytes("q.bin"),
            };

            this.rsa = RSA.Create();
            this.rsa.ImportParameters(this.parameters);
        }

        [Benchmark]
        public X509Certificate2 CopyWithPrivateKey()
        {
            using (var newRsa = RSA.Create())
            {
                newRsa.ImportParameters(this.parameters);
                return certificate.CopyWithPrivateKey(newRsa);
            }
        }

        [Benchmark]
        public X509Certificate2 CopyWithPrivateKeyReuseRSA()
        {
            return certificate.CopyWithPrivateKey(this.rsa);
        }

        [Benchmark]
        public RSA CreateRSA()
        {
            return RSA.Create();
        }
    }
}
