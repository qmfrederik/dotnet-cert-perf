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
        }

        [Benchmark]
        public X509Certificate2 CopyWithPrivateKey()
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(parameters);
                return certificate.CopyWithPrivateKey(rsa);
            }
        }
    }
}
