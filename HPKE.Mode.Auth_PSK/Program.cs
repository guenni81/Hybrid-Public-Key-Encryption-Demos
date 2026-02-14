using System;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace HPKE.Mode.Auth_PSK;

internal static class Program
{
    private static readonly KeyDerivationAlgorithm HkdfSha256 = new HkdfSha256();

    private static void Main()
    {
        /*
         * Demo safety notice:
         * This program prints private keys and shared secrets to the console.
         * Never do this in production systems.
         */
        Console.WriteLine("DEMO ONLY: printing private keys and secrets is insecure. Never use this approach in production.");
        Console.WriteLine();

        /*
         * RFC 9180 ciphersuite identifiers:
         * KEM = DHKEM(X25519, HKDF-SHA256)
         * KDF = HKDF-SHA256
         * AEAD = AES-256-GCM
         */
        const ushort KemId = 0x0020;
        const ushort KdfId = 0x0001;
        const ushort AeadId = 0x0002;

        /* RFC 9180, Section 5.1 mode table: Auth+PSK = 0x03. */
        const byte ModeAuthPsk = 0x03;

        /* AES-256-GCM parameters from RFC 9180, Section 7.3. */
        const int Nk = 32;
        const int Nn = 12;
        const int Nt = 16;

        /*
         * Keep info/aad the same on both sides.
         * info could be empty per RFC, but this demo uses a constant label.
         */
        byte[] info = Encoding.UTF8.GetBytes("hpke-auth-psk-demo-info");
        byte[] aad = Encoding.UTF8.GetBytes("hpke-auth-psk-demo-aad");

        /*
         * RFC 9180, Section 5:
         * suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
         */
        byte[] suiteId = Concat(
            Encoding.ASCII.GetBytes("HPKE"),
            I2Osp2(KemId),
            I2Osp2(KdfId),
            I2Osp2(AeadId));

        /*
         * RFC 9180, Section 4.1:
         * kem_suite_id = "KEM" || I2OSP(kem_id,2)
         */
        byte[] kemSuiteId = Concat(
            Encoding.ASCII.GetBytes("KEM"),
            I2Osp2(KemId));

        /* Demo-only export settings for printing secrets. */
        var keyParams = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        var ssParams = new SharedSecretCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        Console.WriteLine("=== 1) Generate receiver static key pair (skR, pkR) ===");
        using var skR = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkR = skR.PublicKey!;
        byte[] skRBytes = skR.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkRBytes = pkR.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skR (DEMO ONLY)", skRBytes);
        PrintBytes("pkR", pkRBytes);
        Console.WriteLine();

        Console.WriteLine("=== 2) Generate sender static auth key pair (skS, pkS) ===");
        using var skS = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkS = skS.PublicKey!;
        byte[] skSBytes = skS.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkSBytes = pkS.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skS (DEMO ONLY)", skSBytes);
        PrintBytes("pkS", pkSBytes);
        Console.WriteLine();

        Console.WriteLine("=== 3) Configure PSK inputs and validate per RFC ===");
        byte[] psk = Encoding.UTF8.GetBytes("auth-psk-demo-secret-32-bytes-minimum");
        byte[] pskId = Encoding.UTF8.GetBytes("auth-psk-id-demo");
        VerifyPskInputs(ModeAuthPsk, psk, pskId);
        PrintBytes("psk (DEMO ONLY)", psk);
        PrintBytes("psk_id", pskId);
        Console.WriteLine();

        Console.WriteLine("=== 4) Sender generates ephemeral key pair (skE, enc) ===");
        using var skE = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkE = skE.PublicKey!;
        byte[] skEBytes = skE.Export(KeyBlobFormat.RawPrivateKey);
        byte[] enc = pkE.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skE (DEMO ONLY)", skEBytes);
        PrintBytes("enc", enc);
        Console.WriteLine();

        Console.WriteLine("=== 5) Sender performs authenticated DHKEM encapsulation ===");
        SharedSecret? senderDh1Secret = KeyAgreementAlgorithm.X25519.Agree(skE, pkR, in ssParams);
        SharedSecret? senderDh2Secret = KeyAgreementAlgorithm.X25519.Agree(skS, pkR, in ssParams);
        if (senderDh1Secret is null || senderDh2Secret is null)
        {
            throw new InvalidOperationException("Sender DHKEM agreement failed.");
        }

        using var senderDh1 = senderDh1Secret;
        using var senderDh2 = senderDh2Secret;
        byte[] dh1 = senderDh1.Export(SharedSecretBlobFormat.RawSharedSecret);
        byte[] dh2 = senderDh2.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh1 = DH(skE, pkR) (DEMO ONLY)", dh1);
        PrintBytes("dh2 = DH(skS, pkR) (DEMO ONLY)", dh2);

        byte[] sharedSecretSender = KemExtractAndExpandAuth(dh1, dh2, enc, pkRBytes, pkSBytes, kemSuiteId);
        PrintBytes("shared_secret (DEMO ONLY)", sharedSecretSender);
        Console.WriteLine();

        Console.WriteLine("=== 6) Sender runs KeySchedule(mode=0x03) with psk and psk_id ===");
        var senderKs = KeyScheduleAuthPsk(ModeAuthPsk, sharedSecretSender, info, psk, pskId, suiteId, Nk, Nn);
        PrintBytes("aead_key (DEMO ONLY)", senderKs.aeadKey);
        PrintBytes("aead_nonce (DEMO ONLY)", senderKs.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 7) Sender encrypts plaintext with AES-256-GCM ===");
        string plaintext = "Hello HPKE Auth+PSK mode";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        PrintBytes("plaintext", plaintextBytes);

        using var senderAeadKey = Key.Import(AeadAlgorithm.Aes256Gcm, senderKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[] ciphertextWithTag = AeadAlgorithm.Aes256Gcm.Encrypt(senderAeadKey, senderKs.aeadNonce, aad, plaintextBytes);
        if (ciphertextWithTag.Length < Nt)
        {
            throw new InvalidOperationException("Ciphertext+tag length is unexpectedly short.");
        }

        PrintBytes("ciphertext_with_tag", ciphertextWithTag);
        Console.WriteLine();

        Console.WriteLine("=== 8) Sender outputs sealed = enc || ciphertext_with_tag ===");
        /*
         * Message format required by this demo:
         * sealed = enc || ciphertext_with_tag
         * Nonce is derived via key schedule and is not transmitted.
         */
        byte[] sealedMessage = Concat(enc, ciphertextWithTag);
        PrintBytes("sealed", sealedMessage);
        PrintBytes("derived nonce (debug only)", senderKs.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 9) Receiver performs authenticated DHKEM decapsulation ===");
        PublicKey encPublic = PublicKey.Import(KeyAgreementAlgorithm.X25519, enc, KeyBlobFormat.RawPublicKey);

        SharedSecret? receiverDh1Secret = KeyAgreementAlgorithm.X25519.Agree(skR, encPublic, in ssParams);
        SharedSecret? receiverDh2Secret = KeyAgreementAlgorithm.X25519.Agree(skR, pkS, in ssParams);
        if (receiverDh1Secret is null || receiverDh2Secret is null)
        {
            throw new InvalidOperationException("Receiver DHKEM agreement failed.");
        }

        using var receiverDh1 = receiverDh1Secret;
        using var receiverDh2 = receiverDh2Secret;
        byte[] rDh1 = receiverDh1.Export(SharedSecretBlobFormat.RawSharedSecret);
        byte[] rDh2 = receiverDh2.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh1 = DH(skR, enc) (DEMO ONLY)", rDh1);
        PrintBytes("dh2 = DH(skR, pkS) (DEMO ONLY)", rDh2);

        byte[] sharedSecretReceiver = KemExtractAndExpandAuth(rDh1, rDh2, enc, pkRBytes, pkSBytes, kemSuiteId);
        PrintBytes("shared_secret (DEMO ONLY)", sharedSecretReceiver);
        Console.WriteLine();

        Console.WriteLine("=== 10) Receiver runs KeySchedule(mode=0x03) and decrypts ===");
        var receiverKs = KeyScheduleAuthPsk(ModeAuthPsk, sharedSecretReceiver, info, psk, pskId, suiteId, Nk, Nn);
        PrintBytes("aead_key (DEMO ONLY)", receiverKs.aeadKey);
        PrintBytes("aead_nonce (DEMO ONLY)", receiverKs.aeadNonce);

        using var receiverAeadKey = Key.Import(AeadAlgorithm.Aes256Gcm, receiverKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[]? recovered = AeadAlgorithm.Aes256Gcm.Decrypt(receiverAeadKey, receiverKs.aeadNonce, aad, ciphertextWithTag);
        if (recovered is null)
        {
            throw new InvalidOperationException("Receiver decryption failed.");
        }

        Console.WriteLine();
        Console.WriteLine("=== 11) Verify recovered plaintext equals original ===");
        PrintBytes("recovered_plaintext", recovered);
        string recoveredText = Encoding.UTF8.GetString(recovered);
        Console.WriteLine("recovered utf8: " + recoveredText);
        Console.WriteLine("match: " + (recoveredText == plaintext));
    }

    private static (byte[] aeadKey, byte[] aeadNonce) KeyScheduleAuthPsk(
        byte mode,
        byte[] sharedSecret,
        byte[] info,
        byte[] psk,
        byte[] pskId,
        byte[] suiteId,
        int nk,
        int nn)
    {
        /*
         * RFC 9180, Section 5.1: VerifyPskInputs(mode, psk, psk_id)
         * must be checked before key schedule proceeds.
         */
        VerifyPskInputs(mode, psk, pskId);

        /*
         * RFC 9180, Section 5.1 KeySchedule(mode, shared_secret, info, psk, psk_id)
         * psk_id_hash          = LabeledExtract("", "psk_id_hash", psk_id)
         * info_hash            = LabeledExtract("", "info_hash", info)
         * key_schedule_context = mode || psk_id_hash || info_hash
         * secret               = LabeledExtract(shared_secret, "secret", psk)
         * key                  = LabeledExpand(secret, "key", key_schedule_context, Nk)
         * base_nonce           = LabeledExpand(secret, "nonce", key_schedule_context, Nn)
         */
        byte[] empty = Array.Empty<byte>();
        byte[] pskIdHash = LabeledExtract(empty, "psk_id_hash", pskId, suiteId);
        byte[] infoHash = LabeledExtract(empty, "info_hash", info, suiteId);
        byte[] keyScheduleContext = Concat(new[] { mode }, pskIdHash, infoHash);

        byte[] secret = LabeledExtract(sharedSecret, "secret", psk, suiteId);
        byte[] aeadKey = LabeledExpand(secret, "key", keyScheduleContext, nk, suiteId);
        byte[] aeadNonce = LabeledExpand(secret, "nonce", keyScheduleContext, nn, suiteId);
        return (aeadKey, aeadNonce);
    }

    private static void VerifyPskInputs(byte mode, byte[] psk, byte[] pskId)
    {
        /*
         * RFC 9180, Section 5.1 VerifyPskInputs:
         * - If mode uses PSK (0x01, 0x03), psk and psk_id MUST both be non-empty.
         * - If mode does not use PSK (0x00, 0x02), psk and psk_id MUST both be empty.
         */
        bool gotPsk = psk.Length > 0;
        bool gotPskId = pskId.Length > 0;
        bool modeUsesPsk = mode is 0x01 or 0x03;

        if (gotPsk != gotPskId)
        {
            throw new InvalidOperationException("VerifyPskInputs failed: psk and psk_id must both be present or both be absent.");
        }

        if (modeUsesPsk && !gotPsk)
        {
            throw new InvalidOperationException("VerifyPskInputs failed: mode requires non-empty psk and psk_id.");
        }

        if (!modeUsesPsk && gotPsk)
        {
            throw new InvalidOperationException("VerifyPskInputs failed: mode requires empty psk and psk_id.");
        }
    }

    private static byte[] KemExtractAndExpandAuth(byte[] dh1, byte[] dh2, byte[] enc, byte[] pkR, byte[] pkS, byte[] kemSuiteId)
    {
        /*
         * RFC 9180, Section 4.1 (DHKEM Auth):
         * dh = dh1 || dh2 where dh1 = DH(skE, pkR) and dh2 = DH(skS, pkR)
         * for encap (receiver does the mirrored decap equations).
         */
        byte[] dh = Concat(dh1, dh2);

        /*
         * RFC 9180, Section 4.1 ExtractAndExpand with required labels/context:
         * eae_prk       = LabeledExtract("", "eae_prk", dh)
         * kem_context   = enc || pkRm || pkSm
         * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
         */
        byte[] empty = Array.Empty<byte>();
        byte[] eaePrk = LabeledExtract(empty, "eae_prk", dh, kemSuiteId);
        byte[] kemContext = Concat(enc, pkR, pkS);
        int nSecret = HkdfSha256.PseudorandomKeySize;
        return LabeledExpand(eaePrk, "shared_secret", kemContext, nSecret, kemSuiteId);
    }

    private static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm, byte[] suiteId)
    {
        /*
         * RFC 9180, Section 4:
         * LabeledExtract(salt, label, ikm) =
         *   HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm)
         */
        byte[] labeledIkm = Concat(
            Encoding.ASCII.GetBytes("HPKE-v1"),
            suiteId,
            Encoding.ASCII.GetBytes(label),
            ikm);
        return HkdfExtractSha256(salt, labeledIkm);
    }

    private static byte[] LabeledExpand(byte[] prk, string label, byte[] info, int length, byte[] suiteId)
    {
        /*
         * RFC 9180, Section 4:
         * LabeledExpand(prk, label, info, L) =
         *   HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
         */
        byte[] labeledInfo = Concat(
            I2Osp2((ushort)length),
            Encoding.ASCII.GetBytes("HPKE-v1"),
            suiteId,
            Encoding.ASCII.GetBytes(label),
            info);
        return HkdfExpandSha256(prk, labeledInfo, length);
    }

    private static byte[] HkdfExtractSha256(byte[] salt, byte[] ikm)
    {
        /*
         * HKDF-Extract from RFC 5869.
         * For empty salt, use HashLen zero bytes (32 for SHA-256).
         */
        byte[] actualSalt = salt.Length == 0 ? new byte[HkdfSha256.PseudorandomKeySize] : salt;
        using var hmac = new HMACSHA256(actualSalt);
        return hmac.ComputeHash(ikm);
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        int hashLen = HkdfSha256.PseudorandomKeySize;
        int n = (length + hashLen - 1) / hashLen;
        if (n > 255)
        {
            throw new InvalidOperationException("HKDF-Expand output too long.");
        }

        byte[] okm = new byte[length];
        byte[] previous = Array.Empty<byte>();
        int offset = 0;

        using var hmac = new HMACSHA256(prk);
        for (byte i = 1; i <= n; i++)
        {
            byte[] input = Concat(previous, info, new[] { i });
            previous = hmac.ComputeHash(input);
            int take = Math.Min(hashLen, length - offset);
            Buffer.BlockCopy(previous, 0, okm, offset, take);
            offset += take;
        }

        return okm;
    }

    private static byte[] I2Osp2(ushort value)
    {
        return
        [
            (byte)(value >> 8),
            (byte)(value & 0xff)
        ];
    }

    private static byte[] Concat(params byte[][] arrays)
    {
        int length = 0;
        foreach (byte[] array in arrays)
        {
            length += array.Length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        foreach (byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, result, offset, array.Length);
            offset += array.Length;
        }

        return result;
    }

    private static void PrintBytes(string label, byte[] data)
    {
        Console.WriteLine($"{label} ({data.Length} bytes): {HexEncode(data)}");
    }

    private static string HexEncode(byte[] data)
    {
        return Convert.ToHexString(data).ToLowerInvariant();
    }
}
