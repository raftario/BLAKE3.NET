using System;
using System.Security.Cryptography;

namespace BLAKE3
{
    public static class Constants
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
            {0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19};

        internal static readonly uint[] MsgPermutation = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
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

        public static uint FromLeBytes(byte[] bytes)
        {
            if (BitConverter.IsLittleEndian)
            {
                return BitConverter.ToUInt32(bytes, 0);
            }

            return (uint) (bytes[3] << 24) | (uint) (bytes[2] << 16) | (uint) (bytes[1] << 8) | bytes[0];
        }

        public static byte[] ToLeBytes(this uint self)
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
            G(ref state, 0, 4, 8, 12, m[0], m[1]);
            G(ref state, 1, 5, 9, 13, m[2], m[3]);
            G(ref state, 2, 6, 10, 14, m[4], m[5]);
            G(ref state, 3, 7, 11, 15, m[6], m[7]);
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
                chainingValue[5], chainingValue[6], chainingValue[7], Constants.Iv[0], Constants.Iv[1], Constants.Iv[2],
                Constants.Iv[3], (uint) counter, (uint) (counter >> 32), blockLen, flags
            };
            var block = (uint[]) blockWords.Clone();

            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);
            Permute(ref block);
            Round(ref state, block);

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
                words[j] = Extensions.FromLeBytes(bytesBlock);

                j++;
            }
        }

        public static Output ParentOutput(uint[] leftChildCv, uint[] rightChildCv, uint[] key, uint flags)
        {
            var blockWords = new uint[16];
            Array.Copy(leftChildCv, 0, blockWords, 0, 8);
            Array.Copy(rightChildCv, 0, blockWords, 8, 8);
            return new Output
            {
                InputChainingValue = key,
                BlockWords = blockWords,
                Counter = 0,
                BlockLen = Constants.BlockLen,
                Flags = Constants.Parent | flags
            };
        }

        public static uint[] ParentCv(uint[] leftChildCv, uint[] rightChildCv, uint[] key, uint flags)
        {
            return ParentOutput(leftChildCv, rightChildCv, key, flags).ChainingValue();
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

        public void RootOutputBytes(ref byte[] outSlice)
        {
            ulong outputBlockCounter = 0;
            for (var i = 0; i < outSlice.Length; i += 2 * (int) Constants.OutLen)
            {
                var words = Functions.Compress(InputChainingValue, BlockWords, outputBlockCounter, BlockLen,
                    Flags | Constants.Root);
                var k = 0;
                for (var j = 0; j < words.Length; j++)
                {
                    Array.Copy(words[j].ToLeBytes(), 0, outSlice, i + k, 4);

                    k += 4;
                }
                outputBlockCounter++;
            }
        }
    }

    internal class ChunkState
    {
        private uint[] _chainingValue;
        public readonly ulong ChunkCounter;
        private byte[] _block;
        private byte _blockLen;
        private byte _blocksCompressed;
        private readonly uint _flags;

        public ChunkState(uint[] key, ulong chunkCounter, uint flags)
        {
            _chainingValue = key;
            ChunkCounter = chunkCounter;
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
                    _chainingValue = Functions.First8Words(Functions.Compress(_chainingValue, blockWords, ChunkCounter,
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
                Counter = ChunkCounter,
                BlockLen = _blockLen,
                Flags = _flags | StartFlag | Constants.ChunkEnd
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
            HashSizeValue = (int) Constants.OutLen * 8;
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

        public BLAKE3() : this(Constants.Iv, 0)
        {
        }

        private static uint[] KeyWordsFromKey(byte[] key)
        {
            if (key.Length != Constants.KeyLen)
            {
                throw new CryptographicException(
                    $"Expected a {Constants.KeyLen} bytes long key, got a {key.Length} long one");
            }

            var keyWords = new uint[8];
            Functions.WordsFromLittleEndianBytes(key, ref keyWords);
            return keyWords;
        }

        public BLAKE3(byte[] key) : this(KeyWordsFromKey(key), Constants.KeyedHash)
        {
            KeyValue = key;
        }

        private void PushStack(uint[] cv)
        {
            _cvStack[_cvStackLen] = cv;
            _cvStackLen++;
        }

        private uint[] PopStack()
        {
            _cvStackLen--;
            return _cvStack[_cvStackLen];
        }

        private void AddChunkChainingValue(uint[] newCv, ulong totalChunks)
        {
            while ((totalChunks & 1) == 0)
            {
                newCv = Functions.ParentCv(PopStack(), newCv, _key, _flags);
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
                    throw new CryptographicException("Tried to set key on a non-clean hasher");
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
            while (i < roof)
            {
                if (_chunkState.Len == Constants.ChunkLen)
                {
                    var chunkCv = _chunkState.Output().ChainingValue();
                    var totalChunks = _chunkState.ChunkCounter + 1;
                    AddChunkChainingValue(chunkCv, totalChunks);
                    _chunkState = new ChunkState(_key, totalChunks, _flags);
                }

                var want = Constants.ChunkLen - _chunkState.Len;
                var take = (int) Math.Min(want, roof - i);
                var input = array.Slice(i, take);
                _chunkState.Update(input);
                i += take;
            }
        }

        protected override byte[] HashFinal()
        {
            var output = _chunkState.Output();
            var parentNodesRemaining = _cvStackLen;
            while (parentNodesRemaining > 0)
            {
                parentNodesRemaining--;
                output = Functions.ParentOutput(_cvStack[parentNodesRemaining], output.ChainingValue(), _key, _flags);
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
                for (var j = 0; j <= 8; j++)
                {
                    _cvStack[i][j] = 0;
                }
            }
            _cvStackLen = 0;
        }

        #endregion
    }
}
