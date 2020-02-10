using System;
using System.Security.Cryptography;

namespace BLAKE3
{
    public static class BLAKE3Constants
    {
        public const uint OutLen = 32;
        public const uint KeyLen = 32;
        internal const uint BlockLen = 64;
        internal const uint ChunkLen = 1024;

        internal const uint ChunkStart = 1 << 0;
        internal const uint ChunkEnd = 1 << 1;
        internal const uint Parent = 1 << 2;
        internal const uint Root = 1 << 3;
        internal const uint KeyedHash = 1 << 4;
        internal const uint DeriveKyContext = 1 << 5;
        internal const uint DeriveKeyMaterial = 1 << 6;

        internal static readonly uint[] Iv =
        {
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19
        };

        internal static readonly uint[] MsgPermutation =
            {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
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

        public static uint FromLeBytes(byte[] bytes, int startIndex)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(bytes, startIndex);
            }

            return (uint) (bytes[3 + startIndex] << 24) |
                   (uint) (bytes[2 + startIndex] << 16) |
                   (uint) (bytes[1 + startIndex] << 8) |
                   bytes[0 + startIndex];
        }

        public static byte[] ToLeBytes(this uint self)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.GetBytes(self);
            }

            return new[]
            {
                (byte) ((self & 0xff000000) >> 24),
                (byte) ((self & 0x00ff0000) >> 16),
                (byte) ((self & 0x0000ff00) >> 8), (byte) (self & 0x000000ff)
            };
        }
    }

    internal static class Functions
    {
        public static unsafe void G(uint* state,
            uint a,
            uint b,
            uint c,
            uint d,
            uint mx,
            uint my)
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

        public static unsafe void Round(uint* state, uint* m)
        {
            G(state, 0, 4, 8, 12, m[0], m[1]);
            G(state, 1, 5, 9, 13, m[2], m[3]);
            G(state, 2, 6, 10, 14, m[4], m[5]);
            G(state, 3, 7, 11, 15, m[6], m[7]);
            G(state, 0, 5, 10, 15, m[8], m[9]);
            G(state, 1, 6, 11, 12, m[10], m[11]);
            G(state, 2, 7, 8, 13, m[12], m[13]);
            G(state, 3, 4, 9, 14, m[14], m[15]);
        }

        public static unsafe void Permute(uint* m)
        {
            var permuted = stackalloc uint[16];
            for (var i = 0; i < 16; i++)
            {
                permuted[i] = m[BLAKE3Constants.MsgPermutation[i]];
            }
            for (var i = 0; i < 16; i++)
            {
                m[i] = permuted[i];
            }
        }

        public static unsafe void Compress(uint[] chainingValue,
            uint[] blockWords,
            ulong counter,
            uint blockLen,
            uint flags,
            uint* output)
        {
            output[0] = chainingValue[0];
            output[1] = chainingValue[1];
            output[2] = chainingValue[2];
            output[3] = chainingValue[3];
            output[4] = chainingValue[4];
            output[5] = chainingValue[5];
            output[6] = chainingValue[6];
            output[7] = chainingValue[7];
            output[8] = BLAKE3Constants.Iv[0];
            output[9] = BLAKE3Constants.Iv[1];
            output[10] = BLAKE3Constants.Iv[2];
            output[11] = BLAKE3Constants.Iv[3];
            output[12] = (uint) counter;
            output[13] = (uint) (counter >> 32);
            output[14] = blockLen;
            output[15] = flags;
            var block = stackalloc uint[16];
            for (var i = 0; i < 16; i++)
            {
                block[i] = blockWords[i];
            }

            Round(output, block);
            Permute(block);
            Round(output, block);
            Permute(block);
            Round(output, block);
            Permute(block);
            Round(output, block);
            Permute(block);
            Round(output, block);
            Permute(block);
            Round(output, block);
            Permute(block);
            Round(output, block);

            for (var i = 0; i < 8; i++)
            {
                output[i] ^= output[i + 8];
                output[i + 8] ^= chainingValue[i];
            }
        }

        public static void WordsFromLittleEndianBytes(byte[] bytes,
            ref uint[] words)
        {
            for (int i = 0, j = 0; i < bytes.Length; i += 4, j++)
            {
                words[j] = Extensions.FromLeBytes(bytes, i);
            }
        }

        public static unsafe Output ParentOutput(uint[] leftChildCv,
            uint* rightChildCv,
            uint[] key,
            uint flags)
        {
            var blockWords = new uint[16];
            Array.Copy(leftChildCv, 0, blockWords, 0, 8);
            for (var i = 8; i < 16; i++)
            {
                blockWords[i] = rightChildCv[i - 8];
            }
            return new Output
            {
                InputChainingValue = key,
                BlockWords = blockWords,
                Counter = 0,
                BlockLen = BLAKE3Constants.BlockLen,
                Flags = BLAKE3Constants.Parent | flags
            };
        }

        public static unsafe void ParentCv(uint[] leftChildCv,
            uint* rightChildCv,
            uint[] key,
            uint flags,
            uint* output)
        {
            ParentOutput(leftChildCv, rightChildCv, key, flags)
                .ChainingValue(output);
        }
    }

    internal class Output
    {
        public uint[] InputChainingValue;
        public uint[] BlockWords;
        public ulong Counter;
        public uint BlockLen;
        public uint Flags;

        public unsafe void ChainingValue(uint* output)
        {
            var compressionOutput = stackalloc uint[16];
            Functions.Compress(InputChainingValue,
                BlockWords,
                Counter,
                BlockLen,
                Flags,
                compressionOutput);
            for (var i = 0; i < 8; i++)
            {
                output[i] = compressionOutput[i];
            }
        }

        public unsafe void RootOutputBytes(ref byte[] outSlice)
        {
            ulong outputBlockCounter = 0;
            var words = stackalloc uint[16];
            for (var i = 0;
                i < outSlice.Length;
                i += 2 * (int) BLAKE3Constants.OutLen)
            {
                Functions.Compress(InputChainingValue,
                    BlockWords,
                    outputBlockCounter,
                    BlockLen,
                    Flags | BLAKE3Constants.Root,
                    words);
                for (int j = 0, k = 0;
                    j < 16 && k < outSlice.Length;
                    j++, k += 4)
                {
                    Array.Copy(words[j].ToLeBytes(), 0, outSlice, i + k, 4);
                }
                outputBlockCounter++;
            }
        }
    }

    internal class ChunkState
    {
        private readonly uint[] _chainingValue;
        public readonly ulong ChunkCounter;
        private byte[] _block;
        private byte _blockLen;
        private byte _blocksCompressed;
        private readonly uint _flags;

        public ChunkState(uint[] key, ulong chunkCounter, uint flags)
        {
            _chainingValue = key;
            ChunkCounter = chunkCounter;
            _block = new byte[BLAKE3Constants.BlockLen];
            _blockLen = 0;
            _blocksCompressed = 0;
            _flags = flags;
        }

        public uint Len =>
            BLAKE3Constants.BlockLen * _blocksCompressed + _blockLen;

        public uint StartFlag =>
            _blocksCompressed == 0 ? BLAKE3Constants.ChunkStart : 0;

        public unsafe void Update(byte[] input)
        {
            var compressionOutput = stackalloc uint[16];
            var blockWords = new uint[16];
            while (input.Length > 0)
            {
                if (_blockLen == BLAKE3Constants.BlockLen)
                {
                    Functions.WordsFromLittleEndianBytes(_block,
                        ref blockWords);
                    Functions.Compress(_chainingValue,
                        blockWords,
                        ChunkCounter,
                        BLAKE3Constants.BlockLen,
                        _flags | StartFlag,
                        compressionOutput);
                    for (var i = 0; i < 8; i++)
                    {
                        _chainingValue[i] = compressionOutput[i];
                    }
                    _blocksCompressed++;
                    _block = new byte[BLAKE3Constants.BlockLen];
                    _blockLen = 0;
                }

                var want = BLAKE3Constants.BlockLen - _blockLen;
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
                Counter = ChunkCounter,
                BlockLen = _blockLen,
                Flags = _flags | StartFlag | BLAKE3Constants.ChunkEnd
            };
        }
    }

    public class BLAKE3 : KeyedHashAlgorithm
    {
        private ChunkState _chunkState;
        private uint[] _key;
        private readonly uint[][] _cvStack;
        private byte _cvStackLen;
        private readonly uint _flags;

        private BLAKE3(uint[] key, uint flags)
        {
            HashSizeValue = (int) BLAKE3Constants.OutLen * 8;
            State = 0;

            _chunkState = new ChunkState(key, 0, flags);
            _key = key;
            _cvStack = new uint[54][];
            for (var i = 0; i < 54; i++)
            {
                _cvStack[i] = new uint[8];
            }
            _cvStackLen = 0;
            _flags = flags;
        }

        public BLAKE3() : this(BLAKE3Constants.Iv, 0)
        {
        }

        private static uint[] KeyWordsFromKey(byte[] key)
        {
            if (key.Length != BLAKE3Constants.KeyLen)
            {
                throw new CryptographicException(
                    $"Expected a {BLAKE3Constants.KeyLen} bytes long key, got a {key.Length} long one");
            }

            var keyWords = new uint[8];
            Functions.WordsFromLittleEndianBytes(key, ref keyWords);
            return keyWords;
        }

        public BLAKE3(byte[] key) : this(KeyWordsFromKey(key),
            BLAKE3Constants.KeyedHash)
        {
            KeyValue = key;
        }

        private unsafe void PushStack(uint* cv)
        {
            for (var i = 0; i < 8; i++)
            {
                _cvStack[_cvStackLen][i] = cv[i];
            }
            _cvStackLen++;
        }

        private uint[] PopStack()
        {
            _cvStackLen--;
            return _cvStack[_cvStackLen];
        }

        private unsafe void AddChunkChainingValue(uint* newCv,
            ulong totalChunks)
        {
            while ((totalChunks & 1) == 0)
            {
                var lefChildCv = PopStack();
                Functions.ParentCv(lefChildCv,
                    newCv,
                    _key,
                    _flags,
                    newCv);
                totalChunks >>= 1;
            }
            PushStack(newCv);
        }

        #region Overrides

        public override byte[] Hash => HashFinal();

        public new int HashSize
        {
            get => HashSizeValue;
            set => HashSizeValue = value;
        }

        public override byte[] Key
        {
            set
            {
                if (State != 0)
                {
                    throw new CryptographicException(
                        "Tried to set key on a non-clean hasher");
                }

                KeyValue = value;
                _key = KeyWordsFromKey(value);
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (State == 0)
            {
                State = 1;
            }

            var roof = ibStart + cbSize;
            var i = ibStart;
            unsafe
            {
                var chunkCv = stackalloc uint[8];
                while (i < roof)
                {
                    if (_chunkState.Len == BLAKE3Constants.ChunkLen)
                    {
                        _chunkState.Output().ChainingValue(chunkCv);
                        var totalChunks = _chunkState.ChunkCounter + 1;
                        AddChunkChainingValue(chunkCv, totalChunks);
                        _chunkState = new ChunkState(_key, totalChunks, _flags);
                    }

                    var want = BLAKE3Constants.ChunkLen - _chunkState.Len;
                    var take = (int) Math.Min(want, roof - i);
                    _chunkState.Update(array.Slice(i, take));
                    i += take;
                }
            }
        }

        protected override byte[] HashFinal()
        {
            var output = _chunkState.Output();
            var parentNodesRemaining = _cvStackLen;
            unsafe
            {
                var rightChildCv = stackalloc uint[8];
                while (parentNodesRemaining > 0)
                {
                    parentNodesRemaining--;
                    output.ChainingValue(rightChildCv);
                    output = Functions.ParentOutput(
                        _cvStack[parentNodesRemaining],
                        rightChildCv,
                        _key,
                        _flags);
                }
            }
            var ret = new byte[HashSizeValue / 8];
            output.RootOutputBytes(ref ret);
            return ret;
        }

        public override void Initialize()
        {
            State = 0;

            _chunkState = new ChunkState(_key, 0, _flags);
            for (var i = 0; i < 54; i++)
            {
                for (var j = 0; j < 8; j++)
                {
                    _cvStack[i][j] = 0;
                }
            }
            _cvStackLen = 0;
        }

        #endregion
    }
}
