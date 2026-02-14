using System.Text;
using NSec.Cryptography;

namespace HPKE.Mode.PSK;

internal static class Program
{
    private static void Main()
    {
        Console.WriteLine("DEMO ONLY: printing private keys and secrets is insecure. Never use this approach in production.");
        Console.WriteLine();

        /*
         * RFC 9180, Sections 7.1/7.2/7.3 identifiers for this fixed demo ciphersuite:
         * KEM  = DHKEM(X25519, HKDF-SHA256) => kem_id  = 0x0020
         * KDF  = HKDF-SHA256                => kdf_id  = 0x0001
         * AEAD = AES-256-GCM                => aead_id = 0x0002
         */
        const ushort KemId = 0x0020;
        const ushort KdfId = 0x0001;
        const ushort AeadId = 0x0002;

        /* RFC 9180, Section 5.1 mode values: mode_psk = 0x01. */
        const byte ModePsk = 0x01;

        /* AES-256-GCM sizes (RFC 9180, Section 7.3): Nk=32, Nn=12, Nt=16. */
        const int Nk = 32;
        const int Nn = 12;

        byte[] info = Encoding.UTF8.GetBytes("hpke-psk-demo-info");
        byte[] aad = Encoding.UTF8.GetBytes("hpke-psk-demo-aad");

        /*
         * RFC 9180, Section 5:
         * suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
         */
        byte[] suiteId = Concat(
            Encoding.ASCII.GetBytes("HPKE"),
            I2osp2(KemId),
            I2osp2(KdfId),
            I2osp2(AeadId));

        /* RFC 9180, Section 4.1: kem_suite_id = "KEM" || I2OSP(kem_id,2). */
        byte[] kemSuiteId = Concat(
            Encoding.ASCII.GetBytes("KEM"),
            I2osp2(KemId));

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

        Console.WriteLine("=== 2) Configure PSK inputs (non-empty in PSK mode) ===");
        byte[] psk = Encoding.UTF8.GetBytes("demo-psk-32-bytes-material-123456");
        byte[] pskId = Encoding.UTF8.GetBytes("demo-psk-id-001");
        VerifyPskInputs(ModePsk, psk, pskId);
        PrintBytes("psk (DEMO ONLY)", psk);
        PrintBytes("psk_id (DEMO ONLY)", pskId);
        Console.WriteLine();

        Console.WriteLine("=== 3) Sender generates ephemeral key pair (skE, enc) ===");
        using var skE = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkE = skE.PublicKey!;
        byte[] skEBytes = skE.Export(KeyBlobFormat.RawPrivateKey);
        byte[] enc = pkE.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skE (DEMO ONLY)", skEBytes);
        PrintBytes("enc", enc);
        Console.WriteLine();

        Console.WriteLine("=== 4) Sender SetupPSKS: KEM encapsulation => shared_secret ===");
        byte[] sharedSecretSender = KemEncap(skE, pkR, enc, pkRBytes, kemSuiteId, ssParams);
        PrintBytes("shared_secret (sender)", sharedSecretSender);
        Console.WriteLine();

        Console.WriteLine("=== 5) Sender KeySchedule(mode=0x01) with psk + psk_id ===");
        var senderKs = KeySchedulePsk(ModePsk, sharedSecretSender, info, psk, pskId, suiteId, Nk, Nn);
        PrintBytes("aead_key (sender)", senderKs.aeadKey);
        PrintBytes("aead_nonce (sender)", senderKs.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 6) Sender Seal (AES-256-GCM) ===");
        string plaintext = "Hello HPKE PSK mode";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        PrintBytes("plaintext", plaintextBytes);

        using var aeadKeySender = Key.Import(AeadAlgorithm.Aes256Gcm, senderKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[] ciphertextWithTag = AeadAlgorithm.Aes256Gcm.Encrypt(aeadKeySender, senderKs.aeadNonce, aad, plaintextBytes);
        PrintBytes("ciphertext_with_tag", ciphertextWithTag);

        /* RFC 9180 message format in this demo: sealed = enc || ciphertext_with_tag. */
        byte[] sealedMessage = Concat(enc, ciphertextWithTag);
        PrintBytes("sealed = enc || ciphertext_with_tag", sealedMessage);
        Console.WriteLine();

        Console.WriteLine("=== 7) Receiver SetupPSKR: decapsulation => shared_secret ===");
        PublicKey encPublic = PublicKey.Import(KeyAgreementAlgorithm.X25519, enc, KeyBlobFormat.RawPublicKey);
        byte[] sharedSecretReceiver = KemDecap(skR, encPublic, enc, pkRBytes, kemSuiteId, ssParams);
        PrintBytes("shared_secret (receiver)", sharedSecretReceiver);
        Console.WriteLine();

        Console.WriteLine("=== 8) Receiver KeySchedule(mode=0x01) with same psk + psk_id ===");
        var receiverKs = KeySchedulePsk(ModePsk, sharedSecretReceiver, info, psk, pskId, suiteId, Nk, Nn);
        PrintBytes("aead_key (receiver)", receiverKs.aeadKey);
        PrintBytes("aead_nonce (receiver)", receiverKs.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 9) Receiver Open and verify plaintext ===");
        using var aeadKeyReceiver = Key.Import(AeadAlgorithm.Aes256Gcm, receiverKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[]? recovered = AeadAlgorithm.Aes256Gcm.Decrypt(aeadKeyReceiver, receiverKs.aeadNonce, aad, ciphertextWithTag);
        if (recovered is null)
        {
            throw new InvalidOperationException("Decryption failed.");
        }

        PrintBytes("recovered_plaintext", recovered);
        string recoveredText = Encoding.UTF8.GetString(recovered);
        Console.WriteLine("recovered utf8: " + recoveredText);
        Console.WriteLine("match: " + (recoveredText == plaintext));
    }

    private static byte[] KemEncap(Key skE, PublicKey pkR, byte[] enc, byte[] pkRm, byte[] kemSuiteId, SharedSecretCreationParameters ssParams)
    {
        /*
         * RFC 9180, Section 4.1 (DHKEM Encap/ExtractAndExpand):
         * dh = DH(skE, pkR)
         * eae_prk = LabeledExtract("", "eae_prk", dh)
         * kem_context = enc || pkRm
         * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
         */
        SharedSecret? dhSecret = KeyAgreementAlgorithm.X25519.Agree(skE, pkR, in ssParams);
        if (dhSecret is null)
        {
            throw new InvalidOperationException("Sender DH failed.");
        }

        using var dh = dhSecret;
        byte[] dhBytes = dh.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh = DH(skE, pkR) (DEMO ONLY)", dhBytes);

        return KemExtractAndExpand(dhBytes, enc, pkRm, kemSuiteId);
    }

    private static byte[] KemDecap(Key skR, PublicKey encPublic, byte[] enc, byte[] pkRm, byte[] kemSuiteId, SharedSecretCreationParameters ssParams)
    {
        /*
         * RFC 9180, Section 4.1 (DHKEM Decap/ExtractAndExpand):
         * dh = DH(skR, enc)
         * kem_context = enc || pkRm
         */
        SharedSecret? dhSecret = KeyAgreementAlgorithm.X25519.Agree(skR, encPublic, in ssParams);
        if (dhSecret is null)
        {
            throw new InvalidOperationException("Receiver DH failed.");
        }

        using var dh = dhSecret;
        byte[] dhBytes = dh.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh = DH(skR, enc) (DEMO ONLY)", dhBytes);

        return KemExtractAndExpand(dhBytes, enc, pkRm, kemSuiteId);
    }

    private static byte[] KemExtractAndExpand(byte[] dh, byte[] enc, byte[] pkRm, byte[] kemSuiteId)
    {
        byte[] eaePrk = LabeledExtract(Array.Empty<byte>(), "eae_prk", dh, kemSuiteId);
        byte[] kemContext = Concat(enc, pkRm);
        int nSecret = new HkdfSha256().PseudorandomKeySize;
        return LabeledExpand(eaePrk, "shared_secret", kemContext, nSecret, kemSuiteId);
    }

    private static (byte[] aeadKey, byte[] aeadNonce) KeySchedulePsk(
        byte mode,
        byte[] sharedSecret,
        byte[] info,
        byte[] psk,
        byte[] pskId,
        byte[] suiteId,
        int nk,
        int nn)
    {
        /* RFC 9180, Section 5.1: VerifyPSKInputs(mode, psk, psk_id). */
        VerifyPskInputs(mode, psk, pskId);

        /*
         * RFC 9180, Section 5.1 KeySchedule for mode=0x01:
         * psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
         * info_hash = LabeledExtract("", "info_hash", info)
         * key_schedule_context = mode || psk_id_hash || info_hash
         * secret = LabeledExtract(shared_secret, "secret", psk)
         * key = LabeledExpand(secret, "key", key_schedule_context, Nk)
         * nonce = LabeledExpand(secret, "nonce", key_schedule_context, Nn)
         */
        byte[] pskIdHash = LabeledExtract(Array.Empty<byte>(), "psk_id_hash", pskId, suiteId);
        byte[] infoHash = LabeledExtract(Array.Empty<byte>(), "info_hash", info, suiteId);
        byte[] keyScheduleContext = Concat(new[] { mode }, pskIdHash, infoHash);
        byte[] secret = LabeledExtract(sharedSecret, "secret", psk, suiteId);
        PrintBytes("secret (DEMO ONLY)", secret);

        byte[] aeadKey = LabeledExpand(secret, "key", keyScheduleContext, nk, suiteId);
        byte[] aeadNonce = LabeledExpand(secret, "nonce", keyScheduleContext, nn, suiteId);
        return (aeadKey, aeadNonce);
    }

    private static void VerifyPskInputs(byte mode, byte[] psk, byte[] pskId)
    {
        /*
         * RFC 9180, Section 5.1 VerifyPSKInputs:
         * - PSK modes (mode 0x01 or 0x03) require both psk and psk_id to be present and non-empty.
         * - Non-PSK modes (mode 0x00 or 0x02) require both psk and psk_id to be empty.
         */
        bool isPskMode = mode is 0x01 or 0x03;
        bool hasPsk = psk.Length > 0;
        bool hasPskId = pskId.Length > 0;

        if (isPskMode && (!hasPsk || !hasPskId))
        {
            throw new InvalidOperationException("PSK mode requires non-empty psk and psk_id (RFC 9180 Section 5.1 VerifyPSKInputs).");
        }

        if (!isPskMode && (hasPsk || hasPskId))
        {
            throw new InvalidOperationException("Non-PSK mode requires empty psk and psk_id (RFC 9180 Section 5.1 VerifyPSKInputs).");
        }
    }

    private static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm, byte[] suiteId)
    {
        /* RFC 9180, Section 4: HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm). */
        byte[] labeledIkm = Concat(
            Encoding.ASCII.GetBytes("HPKE-v1"),
            suiteId,
            Encoding.ASCII.GetBytes(label),
            ikm);
        return HkdfExtractSha256(salt, labeledIkm);
    }

    private static byte[] LabeledExpand(byte[] prk, string label, byte[] info, int length, byte[] suiteId)
    {
        /* RFC 9180, Section 4: HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L). */
        byte[] labeledInfo = Concat(
            I2osp2((ushort)length),
            Encoding.ASCII.GetBytes("HPKE-v1"),
            suiteId,
            Encoding.ASCII.GetBytes(label),
            info);
        return HkdfExpandSha256(prk, labeledInfo, length);
    }

    private static byte[] HkdfExtractSha256(byte[] salt, byte[] ikm)
    {
        byte[] actualSalt = salt.Length == 0 ? new byte[32] : salt;
        return new HkdfSha256().Extract(ikm, actualSalt);
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        return new HkdfSha256().Expand(prk, info, length);
    }

    private static byte[] I2osp2(ushort value)
    {
        return [(byte)(value >> 8), (byte)(value & 0xFF)];
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (byte[] part in parts)
        {
            total += part.Length;
        }

        byte[] output = new byte[total];
        int offset = 0;
        foreach (byte[] part in parts)
        {
            Buffer.BlockCopy(part, 0, output, offset, part.Length);
            offset += part.Length;
        }

        return output;
    }

    private static void PrintBytes(string label, byte[] value)
    {
        Console.WriteLine($"{label} ({value.Length} bytes): {HexEncode(value)}");
    }

    private static string HexEncode(byte[] value)
    {
        var sb = new StringBuilder(value.Length * 2);
        foreach (byte b in value)
        {
            sb.Append(b.ToString("x2"));
        }

        return sb.ToString();
    }
}
