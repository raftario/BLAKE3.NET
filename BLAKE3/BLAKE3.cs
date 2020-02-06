using System;

namespace BLAKE3
{
    internal static class Constants
    {
        public const uint OutLen = 32;
        public const uint KeyLen = 32;
        public const uint BlockLen = 64;
        public const uint ChunkLen = 1024;

        public const uint ChunkStart = 1 << 0;
        public const uint ChunkEnd = 1 << 1;
        public const uint Parent = 1 << 2;
        public const uint Root = 1 << 3;
        public const uint KeyedHash = 1 << 4;
        public const uint DeriveKyContext = 1 << 5;
        public const uint DeriveKeyMaterial = 1 << 6;

        public static readonly uint[] IV =
            {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

        public static readonly uint[] MsgPermutation = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    }

    internal static class Extensions
    {
        public static uint RotateRight(this uint self, int count)
        {
            return (self >> count) | (self << (32 - count));
        }

        public static T[] Slice<T>(this T[] self, int index, int length)
        {
            var slice = new T[length];
            Array.Copy(self, index, slice, 0, length);
            return slice;
        }

        public static uint FromLEBytes(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(bytes, 0);
            }

            return (uint) (bytes[3] << 24) | (uint) (bytes[2] << 16) | (uint) (bytes[1] << 8) | bytes[0];
        }

        public static byte[] ToLEBytes(this uint self)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.GetBytes(self);
            }

            return new[]
            {
                (byte) ((self & 0xff000000) >> 24), (byte) ((self & 0x00ff0000) >> 16),
                (byte) ((self & 0x0000ff00) >> 8), (byte) (self & 0x000000ff)
            };
        }
    }

    internal static class Functions
    {
        // The mixing function, G, which mixes either a column or a diagonal.
        public static void G(ref uint[] state, uint a, uint b, uint c, uint d, uint mx, uint my)
        {
            state[a] = state[a] + state[b] + mx;
            state[d] = (state[d] ^ state[a]).RotateRight(16);
            state[c] = state[c] + state[d];
            state[b] = (state[b] ^ state[c]).RotateRight(12);
            state[a] = state[a] + state[b] + my;
            state[d] = (state[d] ^ state[a]).RotateRight(8);
            state[c] = state[c] + state[d];
            state[b] = (state[b] ^ state[c]).RotateRight(7);
        }

        public static void Round(ref uint[] state, uint[] m)
        {
            // Mix the columns.
            G(ref state, 0, 4, 8, 12, m[0], m[1]);
            G(ref state, 1, 5, 9, 13, m[2], m[3]);
            G(ref state, 2, 6, 10, 14, m[4], m[5]);
            G(ref state, 3, 7, 11, 15, m[6], m[7]);
            // Mix the diagonals.
            G(ref state, 0, 5, 10, 15, m[8], m[9]);
            G(ref state, 1, 6, 11, 12, m[10], m[11]);
            G(ref state, 2, 7, 8, 13, m[12], m[13]);
            G(ref state, 3, 4, 9, 14, m[14], m[15]);
        }

        public static void Permute(ref uint[] m)
        {
            var permuted = new uint[16];
            for (var i = 0; i < 16; i++)
            {
                permuted[i] = m[Constants.MsgPermutation[i]];
            }
            m = permuted;
        }

        public static uint[] Compress(uint[] chainingValue, uint[] blockWords, ulong counter, uint blockLen, uint flags)
        {
            uint[] state =
            {
                chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3], chainingValue[4],
                chainingValue[5], chainingValue[6], chainingValue[7], Constants.IV[0], Constants.IV[1], Constants.IV[2],
                Constants.IV[3], (uint) counter, (uint) (counter >> 32), blockLen, flags
            };
            var block = (uint[]) blockWords.Clone();

            Round(ref state, block); // round 1
            Permute(ref block);
            Round(ref state, block); // round 2
            Permute(ref block);
            Round(ref state, block); // round 3
            Permute(ref block);
            Round(ref state, block); // round 4
            Permute(ref block);
            Round(ref state, block); // round 5
            Permute(ref block);
            Round(ref state, block); // round 6
            Permute(ref block);
            Round(ref state, block); // round 7

            for (var i = 0; i < 8; i++)
            {
                state[i] ^= state[i + 8];
                state[i + 8] ^= chainingValue[i];
            }
            return state;
        }

        public static uint[] First8Words(uint[] compressionOutput)
        {
            return compressionOutput.Slice(0, 8);
        }

        public static void WordsFromLittleEndianBytes(byte[] bytes, ref uint[] words)
        {
            var j = 0;
            for (var i = 0; i < bytes.Length; i += 4)
            {
                var bytesBlock = bytes.Slice(i, 4);
                words[j] = Extensions.FromLEBytes(bytesBlock);

                j++;
            }
        }
    }

    internal class Output
    {
        public uint[] InputChainingValue;
        public uint[] BlockWords;
        public ulong Counter;
        public uint BlockLen;
        public uint Flags;

        public uint[] ChainingValue()
        {
            return Functions.First8Words(Functions.Compress(InputChainingValue, BlockWords, Counter, BlockLen, Flags));
        }

        public void RootOutputBytes(ref uint[] outSlice)
        {
            ulong outputBlockCounter = 0;
            for (var i = 0; i < outSlice.Length; i += 2 * (int) Constants.OutLen)
            {
                var words = Functions.Compress(InputChainingValue, BlockWords, outputBlockCounter, BlockLen,
                    Flags | Constants.Root);
                var k = 0;
                for (var j = 0; j < words.Length; j++)
                {
                    Array.Copy(words[j].ToLEBytes(), 0, outSlice, i + k, 4);

                    k += 4;
                }
                outputBlockCounter++;
            }
        }
    }

    internal class ChunkState
    {
        private uint[] _chainingValue;
        private readonly ulong _chunkCounter;
        private byte[] _block;
        private byte _blockLen;
        private byte _blocksCompressed;
        private readonly uint _flags;

        public ChunkState(uint[] key, ulong chunkCounter, uint flags)
        {
            _chainingValue = key;
            _chunkCounter = chunkCounter;
            _block = new byte[Constants.BlockLen];
            _blockLen = 0;
            _blocksCompressed = 0;
            _flags = flags;
        }

        public uint Len => Constants.BlockLen * _blocksCompressed + _blockLen;

        public uint StartFlag => _blocksCompressed == 0 ? Constants.ChunkStart : 0;

        public void Update(byte[] input)
        {
            while (input.Length > 0)
            {
                if (_blockLen == Constants.BlockLen)
                {
                    var blockWords = new uint[16];
                    Functions.WordsFromLittleEndianBytes(_block, ref blockWords);
                    _chainingValue = Functions.First8Words(Functions.Compress(_chainingValue, blockWords, _chunkCounter,
                        Constants.BlockLen, _flags | StartFlag));
                    _blocksCompressed++;
                    _block = new byte[Constants.BlockLen];
                    _blockLen = 0;
                }

                var want = Constants.BlockLen - _blockLen;
                var take = Math.Min(want, input.Length);
                Array.Copy(input, 0, _block, _blockLen, take);
                _blockLen += (byte) take;
                input = input.Slice((int) take, (int) (input.Length - take));
            }
        }

        public Output Output()
        {
            var blockWords = new uint[16];
            Functions.WordsFromLittleEndianBytes(_block, ref blockWords);
            return new Output
            {
                InputChainingValue = _chainingValue,
                BlockWords = blockWords,
                Counter = _chunkCounter,
                BlockLen = _blockLen,
                Flags = _flags | StartFlag | Constants.ChunkEnd
            };
        }
    }

    // TODO: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs#L248
}
