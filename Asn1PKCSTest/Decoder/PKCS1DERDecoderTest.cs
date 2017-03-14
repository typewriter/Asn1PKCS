﻿using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using Asn1PKCS.Decoder;
using System.Security.Cryptography;

namespace Asn1PKCSTest.Decoder
{
    [TestClass]
    public class PKCS1DERDecoderTest
    {
        [TestMethod]
        public void DecodePublicKeyTest_512bit()
        {
            RSAParameters expectedRsaParams = new RSAParameters();
            expectedRsaParams.Modulus = new byte[] { 0x00, 0xCE, 0x9D, 0xCC, 0x96, 0x9C, 0xC5, 0xC9, 0x9A, 0x79, 0x1C, 0xE5, 0xBA, 0xA6, 0x46, 0xFE, 0x7E, 0xC7, 0xF2, 0x8A, 0x7A, 0xCE, 0x6E, 0x04, 0x79, 0x28, 0x8B, 0x5A, 0xF2, 0xC0, 0x22, 0xE0, 0xE1, 0x82, 0x75, 0x77, 0xE0, 0x6F, 0x5D, 0x22, 0x5B, 0x43, 0xE6, 0xD0, 0x74, 0x45, 0x9C, 0xA6, 0x8A, 0xCD, 0x79, 0x8A, 0x3C, 0x85, 0x82, 0xC8, 0x40, 0x76, 0x54, 0xCF, 0x54, 0x8B, 0x89, 0x92, 0x99 };
            expectedRsaParams.Exponent = new byte[] { 0x01, 0x00, 0x01 };

            string derBase64EncodedString = "MEgCQQDOncyWnMXJmnkc5bqmRv5+x/KKes5uBHkoi1rywCLg4YJ1d+BvXSJbQ+bQdEWcporNeYo8hYLIQHZUz1SLiZKZAgMBAAE=";

            RSAParameters actualRsaParams = PKCS1DERDecoder.DecodePublicKey(Convert.FromBase64String(derBase64EncodedString));
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParams.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParams.Exponent);

            RSAParameters actualRsaParamsFromB64 = PKCS1DERDecoder.DecodePublicKey(derBase64EncodedString);
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParamsFromB64.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParamsFromB64.Exponent);
        }

        [TestMethod]
        public void DecodePrivateKeyTest_512bit()
        {
            RSAParameters expectedRsaParams = new RSAParameters();
            expectedRsaParams.Modulus = new byte[] { 0x00, 0xCE, 0x9D, 0xCC, 0x96, 0x9C, 0xC5, 0xC9, 0x9A, 0x79, 0x1C, 0xE5, 0xBA, 0xA6, 0x46, 0xFE, 0x7E, 0xC7, 0xF2, 0x8A, 0x7A, 0xCE, 0x6E, 0x04, 0x79, 0x28, 0x8B, 0x5A, 0xF2, 0xC0, 0x22, 0xE0, 0xE1, 0x82, 0x75, 0x77, 0xE0, 0x6F, 0x5D, 0x22, 0x5B, 0x43, 0xE6, 0xD0, 0x74, 0x45, 0x9C, 0xA6, 0x8A, 0xCD, 0x79, 0x8A, 0x3C, 0x85, 0x82, 0xC8, 0x40, 0x76, 0x54, 0xCF, 0x54, 0x8B, 0x89, 0x92, 0x99 };
            expectedRsaParams.Exponent = new byte[] { 0x01, 0x00, 0x01 };
            expectedRsaParams.D = new byte[] { 0x2C, 0x7A, 0x53, 0xBC, 0x68, 0x6B, 0x3B, 0x87, 0x01, 0x63, 0x73, 0x20, 0xC7, 0x02, 0xA9, 0x6E, 0x69, 0x64, 0x90, 0xE2, 0xF6, 0xE5, 0x40, 0x19, 0x44, 0xDD, 0x1A, 0xEA, 0xFE, 0xE9, 0x83, 0x37, 0x25, 0x73, 0xEC, 0x37, 0x9B, 0xA5, 0x91, 0xBF, 0x8F, 0xD7, 0x46, 0x4A, 0xC4, 0xD2, 0x05, 0x7C, 0x53, 0xC2, 0x6A, 0xB2, 0xC2, 0x6D, 0x91, 0x43, 0x78, 0x7E, 0x3C, 0x2A, 0x75, 0x47, 0x28, 0x01 };
            expectedRsaParams.P = new byte[] { 0x00, 0xE8, 0x97, 0xFC, 0xE0, 0xED, 0xA1, 0xA0, 0xF6, 0xC2, 0x35, 0xB8, 0xBA, 0x2D, 0x78, 0x93, 0xE5, 0x74, 0xFC, 0xE1, 0xAD, 0x32, 0xDC, 0xCB, 0x56, 0xB8, 0xE7, 0x57, 0x1D, 0x0E, 0x6C, 0x46, 0x41 };
            expectedRsaParams.Q = new byte[] { 0x00, 0xE3, 0x68, 0x97, 0x75, 0x87, 0x71, 0xF4, 0x20, 0x2D, 0x5F, 0x1B, 0x9B, 0xFD, 0x0D, 0x9A, 0x55, 0x56, 0x2F, 0xE4, 0xC8, 0x47, 0xAE, 0xB4, 0x17, 0xF1, 0x82, 0xDE, 0x9E, 0x62, 0x97, 0xA6, 0x59 };
            expectedRsaParams.DP = new byte[] { 0x1B, 0x22, 0xD0, 0x4F, 0xF5, 0xA9, 0x6B, 0xBC, 0x1E, 0x40, 0x62, 0x42, 0xE6, 0x57, 0x30, 0xFA, 0x0E, 0x42, 0x0A, 0x9A, 0x48, 0x5A, 0xD6, 0x26, 0x52, 0x00, 0x3B, 0x7B, 0x9A, 0x59, 0x2B, 0x81 };
            expectedRsaParams.DQ = new byte[] { 0x13, 0x16, 0x8B, 0x68, 0x0D, 0x17, 0x6E, 0x93, 0x68, 0xDB, 0x8B, 0xD8, 0xBB, 0x13, 0xF2, 0x39, 0x69, 0x83, 0x99, 0xA3, 0x8A, 0x08, 0xCB, 0x0B, 0x1B, 0x75, 0x8D, 0xB4, 0x23, 0xB8, 0x70, 0xF9 };
            expectedRsaParams.InverseQ = new byte[] { 0x52, 0x89, 0xDD, 0x58, 0x69, 0x94, 0xFC, 0x07, 0x25, 0xD6, 0x89, 0xA4, 0x35, 0x6C, 0xD9, 0xE1, 0xDC, 0xAC, 0x77, 0xD6, 0xBF, 0xF1, 0xE4, 0x55, 0xA9, 0x71, 0xF5, 0xDC, 0x1B, 0xDE, 0xA5, 0xF7 };

            string derBase64EncodedString = "MIIBOQIBAAJBAM6dzJacxcmaeRzluqZG/n7H8op6zm4EeSiLWvLAIuDhgnV34G9dIltD5tB0RZymis15ijyFgshAdlTPVIuJkpkCAwEAAQJALHpTvGhrO4cBY3MgxwKpbmlkkOL25UAZRN0a6v7pgzclc+w3m6WRv4/XRkrE0gV8U8JqssJtkUN4fjwqdUcoAQIhAOiX/ODtoaD2wjW4ui14k+V0/OGtMtzLVrjnVx0ObEZBAiEA42iXdYdx9CAtXxub/Q2aVVYv5MhHrrQX8YLenmKXplkCIBsi0E/1qWu8HkBiQuZXMPoOQgqaSFrWJlIAO3uaWSuBAiATFotoDRduk2jbi9i7E/I5aYOZo4oIywsbdY20I7hw+QIgUondWGmU/Acl1omkNWzZ4dysd9a/8eRVqXH13Bvepfc=";

            RSAParameters actualRsaParams = PKCS1DERDecoder.DecodePrivateKey(Convert.FromBase64String(derBase64EncodedString));
            CollectionAssert.AreEqual(expectedRsaParams.Modulus, actualRsaParams.Modulus);
            CollectionAssert.AreEqual(expectedRsaParams.Exponent, actualRsaParams.Exponent);
            CollectionAssert.AreEqual(expectedRsaParams.D, actualRsaParams.D);
            CollectionAssert.AreEqual(expectedRsaParams.P, actualRsaParams.P);
            CollectionAssert.AreEqual(expectedRsaParams.Q, actualRsaParams.Q);
            CollectionAssert.AreEqual(expectedRsaParams.DP, actualRsaParams.DP);
            CollectionAssert.AreEqual(expectedRsaParams.DQ, actualRsaParams.DQ);
            CollectionAssert.AreEqual(expectedRsaParams.InverseQ, actualRsaParams.InverseQ);

            RSAParameters actualRsaParamsFromB64 = PKCS1DERDecoder.DecodePrivateKey(derBase64EncodedString);
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
