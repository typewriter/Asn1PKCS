using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Asn1PKCS.Decoder;
using System.Security.Cryptography;

namespace Asn1PKCSTest.Decoder
{
    [TestClass]
    public class PKCS8DERDecoderTest
    {
        [TestMethod]
        public void DecodePublicKeyTest_384bit()
        {
            RSAParameters expectedRsaParams = new RSAParameters();
            expectedRsaParams.Modulus = new byte[] { 0x00, 0xB0, 0xDB, 0x23, 0xC3, 0x58, 0xBD, 0x7A, 0x2C, 0x34, 0xDF, 0x52, 0x63, 0x40, 0xB3, 0x0A, 0xAF, 0x1C, 0xF1, 0x9B, 0xF6, 0x50, 0x9A, 0x52, 0xB7, 0x73, 0x3D, 0xD0, 0xB7, 0xBE, 0x9C, 0xA6, 0x9A, 0x4F, 0x2C, 0xA9, 0xCC, 0xE2, 0x96, 0x14, 0xE4, 0x2F, 0x35, 0xAA, 0x03, 0x34, 0x56, 0xD6, 0xD9 };
            expectedRsaParams.Exponent = new byte[] { 0x11 };

            string derBase64EncodedString = "MEowDQYJKoZIhvcNAQEBBQADOQAwNgIxALDbI8NYvXosNN9SY0CzCq8c8Zv2UJpSt3M90Le+nKaaTyypzOKWFOQvNaoDNFbW2QIBEQ==";

            RSAParameters actualRsaParams = PKCS8DERDecoder.DecodePublicKey(Convert.FromBase64String(derBase64EncodedString));
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParams.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParams.Exponent);

            RSAParameters actualRsaParamsFromB64 = PKCS8DERDecoder.DecodePublicKey(derBase64EncodedString);
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParamsFromB64.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParamsFromB64.Exponent);
        }

        [TestMethod]
        public void DecodePrivateKeyTest_384bit()
        {
            RSAParameters expectedRsaParams = new RSAParameters();
            expectedRsaParams.Modulus = new byte[] { 0x00, 0xB0, 0xDB, 0x23, 0xC3, 0x58, 0xBD, 0x7A, 0x2C, 0x34, 0xDF, 0x52, 0x63, 0x40, 0xB3, 0x0A, 0xAF, 0x1C, 0xF1, 0x9B, 0xF6, 0x50, 0x9A, 0x52, 0xB7, 0x73, 0x3D, 0xD0, 0xB7, 0xBE, 0x9C, 0xA6, 0x9A, 0x4F, 0x2C, 0xA9, 0xCC, 0xE2, 0x96, 0x14, 0xE4, 0x2F, 0x35, 0xAA, 0x03, 0x34, 0x56, 0xD6, 0xD9 };
            expectedRsaParams.Exponent = new byte[] { 0x11 };
            expectedRsaParams.D = new byte[] { 0x13, 0x81, 0x94, 0xE2, 0xB8, 0xD8, 0xA9, 0xB5, 0xD1, 0x20, 0x29, 0x16, 0x3D, 0xB9, 0x64, 0xF1, 0x6E, 0x7C, 0x87, 0xCA, 0x39, 0xD4, 0xC9, 0x1F, 0x58, 0x09, 0x5A, 0x9B, 0x5D, 0x6B, 0x82, 0x4A, 0x7D, 0xC5, 0x11, 0x89, 0xA6, 0xC0, 0x46, 0x3F, 0x43, 0x71, 0xC2, 0x1D, 0xF3, 0x86, 0xFC, 0xC1 };
            expectedRsaParams.P = new byte[] { 0x00, 0xE2, 0x62, 0xB3, 0xE3, 0x51, 0x04, 0xA9, 0x19, 0xD4, 0xEF, 0x3B, 0xFB, 0x79, 0xF2, 0x91, 0xC7, 0x4F, 0x61, 0xB0, 0x19, 0x6E, 0xF6, 0x7A, 0x69 };
            expectedRsaParams.Q = new byte[] { 0x00, 0xC7, 0xFD, 0xC5, 0x31, 0xA7, 0x1E, 0x93, 0x65, 0x9F, 0x86, 0xF0, 0xF1, 0x5E, 0xA1, 0x06, 0x34, 0x9E, 0x77, 0x3C, 0x0D, 0x69, 0xA9, 0x8A, 0xF1 };
            expectedRsaParams.DP = new byte[] { 0x6A, 0x88, 0xCD, 0x1F, 0xAD, 0xA7, 0xD7, 0x1B, 0x37, 0x07, 0x2B, 0x49, 0x2A, 0x54, 0x08, 0x5D, 0xCB, 0x00, 0xCB, 0x57, 0x43, 0x46, 0xD0, 0x31 };
            expectedRsaParams.DQ = new byte[] { 0x5E, 0x1D, 0x11, 0x80, 0xC7, 0x1D, 0x72, 0x8A, 0x2C, 0xF4, 0x35, 0x26, 0x4A, 0xA6, 0x21, 0x09, 0xB3, 0xFB, 0xE0, 0x06, 0x4F, 0xD7, 0x50, 0x71 };
            expectedRsaParams.InverseQ = new byte[] { 0x10, 0x41, 0xF4, 0xCE, 0x89, 0x5F, 0xA1, 0xB4, 0xB4, 0xA8, 0x76, 0x64, 0xEC, 0x60, 0x32, 0x66, 0x1D, 0x24, 0x6F, 0xA4, 0x12, 0x03, 0x1E, 0xFF };

            string derBase64EncodedString = "MIIBBwIBADANBgkqhkiG9w0BAQEFAASB8jCB7wIBAAIxALDbI8NYvXosNN9SY0CzCq8c8Zv2UJpSt3M90Le+nKaaTyypzOKWFOQvNaoDNFbW2QIBEQIwE4GU4rjYqbXRICkWPblk8W58h8o51MkfWAlam11rgkp9xRGJpsBGP0Nxwh3zhvzBAhkA4mKz41EEqRnU7zv7efKRx09hsBlu9nppAhkAx/3FMacek2WfhvDxXqEGNJ53PA1pqYrxAhhqiM0frafXGzcHK0kqVAhdywDLV0NG0DECGF4dEYDHHXKKLPQ1JkqmIQmz++AGT9dQcQIYEEH0zolfobS0qHZk7GAyZh0kb6QSAx7/";

            RSAParameters actualRsaParams = PKCS8DERDecoder.DecodePrivateKey(Convert.FromBase64String(derBase64EncodedString));
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParams.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParams.Exponent);
            CollectionAssert.AreEqual(expectedRsaParams.D, actualRsaParams.D);
            CollectionAssert.AreEqual(expectedRsaParams.P, actualRsaParams.P);
            CollectionAssert.AreEqual(expectedRsaParams.Q, actualRsaParams.Q);
            CollectionAssert.AreEqual(expectedRsaParams.DP, actualRsaParams.DP);
            CollectionAssert.AreEqual(expectedRsaParams.DQ, actualRsaParams.DQ);
            CollectionAssert.AreEqual(expectedRsaParams.InverseQ, actualRsaParams.InverseQ);

            RSAParameters actualRsaParamsFromB64 = PKCS8DERDecoder.DecodePrivateKey(derBase64EncodedString);
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParamsFromB64.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParamsFromB64.Exponent);
            CollectionAssert.AreEqual(expectedRsaParams.D, actualRsaParamsFromB64.D);
            CollectionAssert.AreEqual(expectedRsaParams.P, actualRsaParamsFromB64.P);
            CollectionAssert.AreEqual(expectedRsaParams.Q, actualRsaParamsFromB64.Q);
            CollectionAssert.AreEqual(expectedRsaParams.DP, actualRsaParamsFromB64.DP);
            CollectionAssert.AreEqual(expectedRsaParams.DQ, actualRsaParamsFromB64.DQ);
            CollectionAssert.AreEqual(expectedRsaParams.InverseQ, actualRsaParamsFromB64.InverseQ);

        }
    }
}
