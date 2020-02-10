using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using Tests.Helpers;
using Xunit;
using BLAKE3;

namespace Tests
{
    public class HashValidityTests
    {
        private static string TestDataPath = 
            Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "TestData");
        private static string DataFile(int i)
            => Path.Combine(TestDataPath, $"test_data_{i}");
        private static string HashFile(int i)
            => Path.Combine(TestDataPath, $"test_data_{i}.b3");

        public static IEnumerable<object?[]> GetHashData(int count)
            => Enumerable.Range(1, count)
                         .Select(i => new object[] 
                         { 
                             File.ReadAllBytes(DataFile(i)), 
                             File.ReadAllBytes(HashFile(i)) 
                         });

        private readonly BLAKE3.BLAKE3 hasher = new BLAKE3.BLAKE3(); 

        [Theory]
        [MemberData(nameof(GetHashData), 4)]
        public void CheckHashing(byte[] input, byte[] expectedHash)
        {
            var hashed = hasher.ComputeHash(input);
            Assert.True(Utilities.BytesEqual(hashed, expectedHash));
        }
    }
}
