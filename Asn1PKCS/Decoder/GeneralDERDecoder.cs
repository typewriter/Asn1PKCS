using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Asn1PKCS.Decoder
{
    /// <summary>
    /// General DER Decoder
    /// </summary>
    internal class GeneralDERDecoder
    {
        /// <summary>
        /// Extract "INTEGER" values recursively.
        /// "INTEGER"値を抽出します。SEQUENCEなどの内側も再帰的に抽出します。
        /// </summary>
        /// <param name="derData"></param>
        /// <returns></returns>
        internal static List<byte[]> ExtractIntegerDatas(byte[] derData)
        {
            List<byte[]> intDataList = new List<byte[]>();

            int index = 0;
            while (index < derData.Length)
            {
                byte tagType = derData[index];
                index++;

                int length = derData[index];
                index++;

                // length >= 128
                if ((length & 0x80) != 0)
                {
                    int lengthLength = length & 0x7F;
                    byte[] lengthBytes = 
                        new byte[4 - lengthLength] // padding (int32)
                        .Concat(derData.Skip(index).Take(lengthLength)).ToArray();

                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(lengthBytes);
                    }
                    length = BitConverter.ToInt32(lengthBytes, 0);
                    index += lengthLength;
                }

                // HACK: DERUtilsを使うべきで、DERUtilsは名前空間を移動したほうがよい
                if (tagType == 0x02)
                {
                    // INTEGER values.
                    byte[] value = derData.Skip(index).Take(length).ToArray();
                    intDataList.Add(value);
                    index += length;
                }
                else if (tagType == 0x04 || tagType == 0x30)
                {
                    // OCTETSTRING, SEQUENCE values.

                }
                else if (tagType == 0x03)
                {
                    // BITSTRING (skip unused bit field)
                    index++;
                }
                else
                {
                    // ELSE
                    index += length;
                }
            }

            return intDataList;
        }
    }
}
