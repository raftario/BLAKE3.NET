using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using BenchmarkDotNet.Jobs;
using System.Linq;

namespace BLAKE3.Benchmarks
{
    [SimpleJob(RuntimeMoniker.NetCoreApp22)]
    [SimpleJob(RuntimeMoniker.NetCoreApp31)]
    [SimpleJob(RuntimeMoniker.CoreRt22)]
    [SimpleJob(RuntimeMoniker.CoreRt31)]
    [SimpleJob(RuntimeMoniker.Net462)]
    [SimpleJob(RuntimeMoniker.Net472)]
    [SimpleJob(RuntimeMoniker.Net48)]
    [SimpleJob(RuntimeMoniker.Mono)]
    [RPlotExporter, HtmlExporter, CsvExporter]
    public class HashSpeedBenchmarks
    {
        private readonly SHA1 sha1 = SHA1.Create();
        private readonly SHA256 sha256 = SHA256.Create();
        private readonly SHA384 sha384 = SHA384.Create();
        private readonly SHA512 sha512 = SHA512.Create();
        private readonly MD5 md5 = MD5.Create();

        private readonly BLAKE3 blake3 = new BLAKE3();

        [ParamsSource(nameof(DataGenerator))]
        public DataWrapper DataWrapper
        {
            get => new DataWrapper(data);
            set => data = value.Data;
        }

        private byte[] data;

        public static IEnumerable<DataWrapper> DataGenerator
            => Enumerable.Range(1, 10)
                         .Select(i => i * 256 * 1024)
                         .Select(i => new DataWrapper(i))
                         .Select(d => d.Randomize());

        [Benchmark, BenchmarkCategory("HashSpeed", "Builtin")]
        public byte[] Sha1() => sha1.ComputeHash(data);

        [Benchmark, BenchmarkCategory("HashSpeed", "Builtin")]
        public byte[] Sha256() => sha256.ComputeHash(data);

        [Benchmark, BenchmarkCategory("HashSpeed", "Builtin")]
        public byte[] Sha384() => sha384.ComputeHash(data);

        [Benchmark, BenchmarkCategory("HashSpeed", "Builtin")]
        public byte[] Sha512() => sha512.ComputeHash(data);

        [Benchmark, BenchmarkCategory("HashSpeed", "Builtin")]
        public byte[] Md5() => md5.ComputeHash(data);

        [Benchmark, BenchmarkCategory("HashSpeed")]
        public byte[] Blake3() => blake3.ComputeHash(data);
    }

    public struct DataWrapper 
    { 
        public byte[] Data { get; }
        public int Length => Data.Length;

        public DataWrapper(int size) : this(new byte[size]) { }
        public DataWrapper(byte[] data) => Data = data;

        public DataWrapper Randomize()
        {
            new Random().NextBytes(Data);
            return this;
        }

        public override string ToString()
            => $"byte[{Length}]";
    }
}
