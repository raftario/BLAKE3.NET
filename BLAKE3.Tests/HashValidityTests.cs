using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using BLAKE3.Tests.Helpers;
using Xunit;

namespace BLAKE3.Tests
{
    public class HashValidityTests
    {
        private static readonly string TestDataPath = 
            Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "TestData");
        private static string DataFile(int i)
            => Path.Combine(TestDataPath, $"test_data_{i}");
        private static byte[] ReadData(int i)
            => File.ReadAllBytes(DataFile(i));
        private static string HashFile(int i)
            => Path.Combine(TestDataPath, $"test_data_{i}.b3");
        private static byte[] ReadHash(int i)
            => File.ReadAllBytes(HashFile(i));

        public static IEnumerable<object?[]> GetHashData(int count)
            => Enumerable.Range(1, count)
                         .Select(i => new object[] { i });

        private readonly BLAKE3 hasher = new BLAKE3(); 

        [Theory]
        [MemberData(nameof(GetHashData), 8)]
        public void CheckHashing(int testRun)
        {
            var input = ReadData(testRun);
            var expectedHash = ReadHash(testRun);

            var hashed = hasher.ComputeHash(input);
            Assert.True(Utilities.BytesEqual(hashed, expectedHash));
        }
    }
}
