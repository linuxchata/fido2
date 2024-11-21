using System;

namespace Shark.Fido2.Core.Helpers
{
    public static class Base64Comparer
    {
        public static bool Compare(string expected, string actual)
        {
            var expectedData = Convert.FromBase64String(expected);
            var actualData = Convert.FromBase64String(actual);

            if (expectedData.Length != actualData.Length)
            {
                return false;
            }

            for (var i = 0; i < expectedData.Length; i++)
            {
                if (expectedData[i] != actualData[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
