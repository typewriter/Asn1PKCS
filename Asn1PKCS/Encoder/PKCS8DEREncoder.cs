using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using static Asn1PKCS.Encoder.DERUtils;

namespace Asn1PKCS.Encoder
{
    /// <summary>
    /// PKCS #8 RSA key ASN.1 Encoder
    /// </summary>
    public class PKCS8DEREncoder
    {
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
            byte[] keySequence = PKCS1DEREncoder.EncodePublicKey(rsaParameters);
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
            byte[] keySequence = PKCS1DEREncoder.EncodePrivateKey(rsaParameters);
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
    }
}
