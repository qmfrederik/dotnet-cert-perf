using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Attributes.Jobs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
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

            var exportedParams = this.rsa.ExportParameters(true);
            this.rsa.VerifyHash(new byte[20], new byte[this.rsa.KeySize >> 3], HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
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

        private readonly SecureRandom secureRandom = new SecureRandom();

        [Benchmark]
        public X509Certificate2 CopyWithPrivateKeyBouncy()
        {
            var cert = DotNetUtilities.FromX509Certificate(certificate);

            Pkcs12Store store = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(cert);
            store.SetCertificateEntry("cert", certEntry);

            var key = GetRsaKeyPair(this.parameters);
            store.SetKeyEntry("cert", new AsymmetricKeyEntry(key), new X509CertificateEntry[] { certEntry });

            using (MemoryStream stream = new MemoryStream())
            {
                store.Save(stream, Array.Empty<char>(), this.secureRandom);
                stream.Position = 0;

                byte[] data = stream.ToArray();

                var x509cert = new X509Certificate2(data, string.Empty, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.UserKeySet);

                // Pre-fetch the private key to make sure the lazy property has been loaded;
                // once the memory stream has been disposed of/array is out of scope, retrieving the private key from the
                // byte array is no longer an option.
                var privateKey = RSACertificateExtensions.GetRSAPrivateKey(x509cert);
                return x509cert;
            }
        }

        public static RsaPrivateCrtKeyParameters GetRsaKeyPair(RSAParameters rp)
        {
            return new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rp.Modulus),
                new BigInteger(1, rp.Exponent),
                new BigInteger(1, rp.D),
                new BigInteger(1, rp.P),
                new BigInteger(1, rp.Q),
                new BigInteger(1, rp.DP),
                new BigInteger(1, rp.DQ),
                new BigInteger(1, rp.InverseQ));
        }
    }
}
