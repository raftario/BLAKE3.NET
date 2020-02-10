using System;
using System.Security.Cryptography;
using BenchmarkDotNet.Running;

namespace BLAKE3.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
            => BenchmarkSwitcher
                .FromAssembly(typeof(Program).Assembly)
                .Run(args);
    }
}
