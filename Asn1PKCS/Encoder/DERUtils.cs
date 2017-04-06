using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1PKCS.Encoder
{
    class DERUtils
    {
        public enum DerType : byte
        {
            Integer = 0x02,
            BitString = 0x03,
            OctetString = 0x04,
            Null = 0x05,
            ObjectIdentifier = 0x06,
            Sequence = 0x30,
        }

        public static byte[] DERTag(DerType derType, int length)
        {
            if (length < 128)
            {
                return new byte[] { (byte)derType, (byte)length };
            }

            // Length is >= 128 bytes
            // DERTag, [0x80 + length], Length
            byte[] lengths = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
            {
                lengths = lengths.Reverse().ToArray();
            }

            // search not 0x00 value
            int startIndex = lengths
                .Select((e, i) => new { data = e, index = i })
                .Where(e => e.data != 0x00)
                .First().index;

            return Enumerable.Concat(
                new byte[] { (byte)derType, (byte)(0x80 + lengths.Length - startIndex) },
                lengths.Skip(startIndex)
            ).ToArray();
        }

        public static byte[] DERTag(DerType derType, byte[] data)
        {
            return Enumerable.Concat(DERTag(derType, data.Length), data).ToArray();
        }

        public static byte[] DERTag(DerType derType, byte[] data, bool unsignedData)
        {
            byte[] signedData = data;
            
            // prepend "positive sign (0x00)" byte
            if (unsignedData && signedData[0] >= 0x80)
            {
                signedData = new byte[] { 0x00 }.Concat(signedData).ToArray();
            }

            return DERTag(derType, signedData);
        }
    }
}
