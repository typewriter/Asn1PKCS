using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Asn1PKCS.Encoder
{
    /// <summary>
    /// PKCS #8 RSA key ASN.1 Encoder
    /// </summary>
    public class PKCS8DEREncoder
    {
        private enum DerType : byte
        {
            Integer = 0x02,
            BitString = 0x03,
            OctetString = 0x04,
            Null = 0x05,
            ObjectIdentifier = 0x06,
            Sequence = 0x30,
        }

        private static readonly byte[] ZeroIntDerData =
            new byte[] { (byte)DerType.Integer, 0x01, 0x00 };
        private static readonly byte[] RsaIdDerData =
            new byte[] { (byte)DerType.ObjectIdentifier, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        private static readonly byte[] NullDerData =
            new byte[] { (byte)DerType.Null, 0x00 };

        /// <summary>
        /// Encode RSAPublicKey in PKCS #8(DER) format.
        /// PKCS #8(DER)形式でRSA公開鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static byte[] EncodePublicKey(RSAParameters rsaParameters)
        {
            // SEQUENCE

            //  - SEQUENCE
            //    - OBJECT IDENTIFIER (PKCS #1 rsaEncryption)
            //    - NULL
            byte[] identifierSequence = DERTag(DerType.Sequence, Enumerable.Concat(RsaIdDerData, NullDerData).ToArray());

            //  - BIT STRING
            //    - SEQUENCE
            //      - INTEGER (modulus)
            //      - INTEGER (exponent)
            byte[] modulus = DERTag(DerType.Integer, rsaParameters.Modulus);
            byte[] exponent = DERTag(DerType.Integer, rsaParameters.Exponent);
            byte[] keySequence = DERTag(DerType.Sequence, Enumerable.Concat(modulus, exponent).ToArray());
            byte[] keyBitString = DERTag(
                DerType.BitString,
                Enumerable.Concat(new byte[] { 0x00 }, keySequence).ToArray()
                );

            // Concatenate
            byte[] asn1Bytes =
                DERTag(DerType.Sequence, Enumerable.Concat(identifierSequence, keyBitString).ToArray());

            return asn1Bytes;
        }

        /// <summary>
        /// Encode RSAPublicKey in PKCS #8(DER) format.
        /// PKCS #8(DER)形式でRSA公開鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static string EncodePublicKeyToBase64(RSAParameters rsaParameters)
        {
            return Convert.ToBase64String(EncodePublicKey(rsaParameters));
        }

        /// <summary>
        /// Encode RSAPrivateKey in PKCS #8(DER) format.
        /// PKCS #8(DER)形式でRSA秘密鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static byte[] EncodePrivateKey(RSAParameters rsaParameters)
        {
            // SEQUENCE

            // - INTEGER (0)
            // - SEQUENCE
            //   - OBJECT IDENTIFIER (PKCS #1 rsaEncryption)
            //   - NULL
            byte[] zeroInteger = ZeroIntDerData;
            byte[] identifierSequence = Enumerable.Concat(
                    DERTag(DerType.Sequence, RsaIdDerData.Length + NullDerData.Length),
                    Enumerable.Concat(RsaIdDerData, NullDerData)
                ).ToArray();

            // - OCTET STRING
            //   - SEQUENCE
            //     - INTEGER (version: 0)
            //     - INTEGER (modulus)
            //     - INTEGER (publicExponent)
            //     - INTEGER (privateExponent)
            //     - INTEGER (prime1)
            //     - INTEGER (prime2)
            //     - INTEGER (exponent1)
            //     - INTEGER (exponent2)
            //     - INTEGER (coefficient)
            // Note: https://msdn.microsoft.com/ja-jp/library/system.security.cryptography.rsaparameters(v=vs.110).aspx
            byte[] version = ZeroIntDerData;
            byte[] modulus = DERTag(DerType.Integer, rsaParameters.Modulus);
            byte[] publicExponent = DERTag(DerType.Integer, rsaParameters.Exponent);
            byte[] privateExponent = DERTag(DerType.Integer, rsaParameters.D);
            byte[] prime1 = DERTag(DerType.Integer, rsaParameters.P);
            byte[] prime2 = DERTag(DerType.Integer, rsaParameters.Q);
            byte[] exponent1 = DERTag(DerType.Integer, rsaParameters.DP);
            byte[] exponent2 = DERTag(DerType.Integer, rsaParameters.DQ);
            byte[] coefficient = DERTag(DerType.Integer, rsaParameters.InverseQ);

            byte[] keySequence = DERTag(
                DerType.Sequence,
                Enumerable.Concat(version, modulus).Concat(publicExponent).Concat(privateExponent).Concat(prime1).Concat(prime2).Concat(exponent1).Concat(exponent2).Concat(coefficient).ToArray()
                );
            byte[] keyOctetString = DERTag(DerType.OctetString, keySequence);


            byte[] asn1Bytes = DERTag(
                DerType.Sequence,
                Enumerable.Concat(zeroInteger, identifierSequence).Concat(keyOctetString).ToArray()
                );
            return asn1Bytes;
        }

        /// <summary>
        /// Encode RSAPrivateKey in PKCS #8(DER) format.
        /// PKCS #8(DER)形式でRSA秘密鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static string EncodePrivateKeyToBase64(RSAParameters rsaParameters)
        {
            return Convert.ToBase64String(EncodePrivateKey(rsaParameters));
        }

        private static byte[] DERTag(DerType derType, int length)
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

        private static byte[] DERTag(DerType derType, byte[] data)
        {
            return Enumerable.Concat(DERTag(derType, data.Length), data).ToArray();
        }
    }
}
