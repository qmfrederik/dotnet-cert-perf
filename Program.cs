using BenchmarkDotNet.Running;

namespace dotnet_cert_perf
{
    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<CopyWithPrivateKeyBenchmarks>();
        }
    }
}
