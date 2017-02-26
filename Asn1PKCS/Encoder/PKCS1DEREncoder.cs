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
    /// PKCS #1 RSA key ASN.1 Encoder
    /// </summary>
    public class PKCS1DEREncoder
    {
        private static readonly byte[] ZeroIntDerData =
            new byte[] { (byte)DerType.Integer, 0x01, 0x00 };

        /// <summary>
        /// Encode RSAPublicKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式でRSA公開鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static byte[] EncodePublicKey(RSAParameters rsaParameters)
        {
            // SEQUENCE
            // - INTEGER (modulus)
            // - INTEGER (exponent)
            byte[] modulus = DERTag(DerType.Integer, rsaParameters.Modulus);
            byte[] exponent = DERTag(DerType.Integer, rsaParameters.Exponent);
            byte[] keySequence = DERTag(DerType.Sequence, Enumerable.Concat(modulus, exponent).ToArray());

            return keySequence;
        }

        /// <summary>
        /// Encode RSAPublicKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式でRSA公開鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static string EncodePublicKeyToBase64(RSAParameters rsaParameters)
        {
            return Convert.ToBase64String(EncodePublicKey(rsaParameters));
        }

        /// <summary>
        /// Encode RSAPrivateKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式でRSA秘密鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static byte[] EncodePrivateKey(RSAParameters rsaParameters)
        {
            // SEQUENCE
            // - INTEGER (version: 0)
            // - INTEGER (modulus)
            // - INTEGER (publicExponent)
            // - INTEGER (privateExponent)
            // - INTEGER (prime1)
            // - INTEGER (prime2)
            // - INTEGER (exponent1)
            // - INTEGER (exponent2)
            // - INTEGER (coefficient)
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

            return keySequence;
        }

        /// <summary>
        /// Encode RSAPrivateKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式でRSA秘密鍵をエンコードします。
        /// </summary>
        /// <param name="rsaParameters"></param>
        /// <returns></returns>
        public static string EncodePrivateKeyToBase64(RSAParameters rsaParameters)
        {
            return Convert.ToBase64String(EncodePrivateKey(rsaParameters));
        }
    }
}