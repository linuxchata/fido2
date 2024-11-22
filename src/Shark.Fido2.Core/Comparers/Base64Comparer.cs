using System;

namespace Shark.Fido2.Core.Comparers
{
    public static class Base64Comparer
    {
        public static bool Compare(string expected, string actual)
        {
            var expectedData = Convert.FromBase64String(expected);
            var actualData = Convert.FromBase64String(actual);

            return BytesArrayComparer.CompareAsSpan(expectedData, actualData);
        }
    }
}
