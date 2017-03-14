using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Asn1PKCS.Decoder
{
    /// <summary>
    /// PKCS #1 RSA key ASN.1 Decoder
    /// </summary>
    public class PKCS1DERDecoder
    { 
        /// <summary>
        /// Decode RSAPublicKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式のRSA公開鍵をデコードします。
        /// </summary>
        /// <param name="derEncodedBytes"></param>
        /// <returns></returns>
        public static RSAParameters DecodePublicKey(byte[] derEncodedBytes)
        {
            List<byte[]> intItems = GeneralDERDecoder.ExtractIntegerDatas(derEncodedBytes);

            RSAParameters rsaParams = new RSAParameters();
            rsaParams.Modulus = intItems[0];
            rsaParams.Exponent = intItems[1];

            return rsaParams;
        }

        /// <summary>
        /// Decode RSAPublicKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式のRSA公開鍵をデコードします。
        /// </summary>
        /// <param name="derBase64EncodedString"></param>
        /// <returns></returns>
        public static RSAParameters DecodePublicKey(string derBase64EncodedString)
        {
            return DecodePublicKey(Convert.FromBase64String(derBase64EncodedString));
        }

        /// <summary>
        /// Decode RSAPrivateKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式のRSA秘密鍵をデコードします。
        /// </summary>
        /// <param name="derEncodedBytes"></param>
        /// <returns></returns>
        public static RSAParameters DecodePrivateKey(byte[] derEncodedBytes)
        {
            List<byte[]> intItems = GeneralDERDecoder.ExtractIntegerDatas(derEncodedBytes);

            RSAParameters rsaParams = new RSAParameters();
            
            rsaParams.Modulus = intItems[1];
            rsaParams.Exponent = intItems[2];
            rsaParams.D = intItems[3];
            rsaParams.P = intItems[4];
            rsaParams.Q = intItems[5];
            rsaParams.DP = intItems[6];
            rsaParams.DQ = intItems[7];
            rsaParams.InverseQ = intItems[8];

            return rsaParams;
        }

        /// <summary>
        /// Decode RSAPrivateKey in PKCS #1(DER) format.
        /// PKCS #1(DER)形式のRSA秘密鍵をデコードします。
        /// </summary>
        /// <param name="derBase64EncodedString"></param>
        /// <returns></returns>
        public static RSAParameters DecodePrivateKey(string derBase64EncodedString)
        {
            return DecodePrivateKey(Convert.FromBase64String(derBase64EncodedString));
        }
    }
}
