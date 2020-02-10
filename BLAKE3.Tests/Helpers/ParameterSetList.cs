using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace BLAKE3.Tests.Helpers
{
    public abstract class ParameterSetListBase : IEnumerable<object?[]>
    {
        private readonly List<object?[]> list = new List<object?[]>();

        protected void AddInternal(params object?[] objs)
            => list.Add(objs);

        public List<object?[]>.Enumerator GetEnumerator()
            => list.GetEnumerator();
        IEnumerator<object?[]> IEnumerable<object?[]>.GetEnumerator()
            => ((IEnumerable<object?[]>)list).GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator()
            => ((IEnumerable)list).GetEnumerator();
    }

    public sealed class ParameterSetList<T1> : ParameterSetListBase
    { public void Add(T1 a) => AddInternal(a); }
    public sealed class ParameterSetList<T1, T2> : ParameterSetListBase
    { public void Add(T1 a, T2 b) => AddInternal(a, b); }
    public sealed class ParameterSetList<T1, T2, T3> : ParameterSetListBase
    { public void Add(T1 a, T2 b, T3 c)  => AddInternal(a, b, c); }
    public sealed class ParameterSetList<T1, T2, T3, T4> : ParameterSetListBase
    { public void Add(T1 a, T2 b, T3 c, T4 d) => AddInternal(a, b, c, d); }
}
