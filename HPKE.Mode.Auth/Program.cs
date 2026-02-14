using System;
using System.Text;
using NSec.Cryptography;

namespace HPKE.Mode.Auth;

internal static class Program
{
    private static void Main()
    {
        /*
         * Security notice for this demo:
         * This sample prints private keys and intermediate secrets,
         * so each step of the HPKE flow can be followed.
         * This is for educational purposes ONLY.
         */
        Console.WriteLine("DEMO ONLY: printing private keys and secrets is insecure. Never use this approach in production.");
        Console.WriteLine();

        /*
         * RFC 9180 ciphersuite (fixed for this demo):
         * - KEM  = DHKEM(X25519, HKDF-SHA256) => kem_id  = 0x0020
         * - KDF  = HKDF-SHA256                => kdf_id  = 0x0001
         * - AEAD = AES-256-GCM                => aead_id = 0x0002
         *
         * Reference:
         * - RFC 9180, Section 7.1 (KEM IDs)
         * - RFC 9180, Section 7.2 (KDF IDs)
         * - RFC 9180, Section 7.3 (AEAD IDs)
         */
        const ushort KemId = 0x0020;
        const ushort KdfId = 0x0001;
        const ushort AeadId = 0x0002;

        /* RFC 9180: Auth mode = 0x02 (table in Section 5.1). */
        const byte ModeAuth = 0x02;

        /*
         * AES-256-GCM parameters:
         * - Nk = 32 byte key
         * - Nn = 12 byte nonce
         * - Nt = 16 byte tag (included in NSec encrypt output format)
         */
        const int Nk = 32;
        const int Nn = 12;

        /*
         * HPKE application context:
         * - info and aad are empty in this demo.
         * - Important: both sides must use the same values.
         */
        byte[] info = Array.Empty<byte>();
        byte[] aad = Array.Empty<byte>();

        /*
         * RFC 9180, Section 5:
         * suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
         *
         * This suite_id is used for the LabeledExtract/LabeledExpand functions
         * in the key schedule.
         */
        byte[] suiteId = Concat(
            Encoding.ASCII.GetBytes("HPKE"),
            I2osp2(KemId),
            I2osp2(KdfId),
            I2osp2(AeadId));

        /*
         * RFC 9180, Section 4.1 (DHKEM):
         * kem_suite_id = "KEM" || I2OSP(kem_id,2)
         *
         * This ID is used ONLY for KEM-internal labeled functions.
         */
        byte[] kemSuiteId = Concat(
            Encoding.ASCII.GetBytes("KEM"),
            I2osp2(KemId));

        /*
         * DEMO ONLY:
         * ExportPolicy allows plaintext export so values can be printed.
         */
        var keyParams = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        var ssParams = new SharedSecretCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        Console.WriteLine("=== 1) Generate receiver static key pair (skR, pkR) ===");
        // skR/pkR = receiver static key (Receiver static key pair)
        using var skR = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkR = skR.PublicKey!;
        byte[] skRBytes = skR.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkRBytes = pkR.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skR", skRBytes);
        PrintBytes("pkR", pkRBytes);
        Console.WriteLine();

        Console.WriteLine("=== 2) Generate sender static auth key pair (skS, pkS) ===");
        // skS/pkS = sender static authentication key
        using var skS = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkS = skS.PublicKey!;
        byte[] skSBytes = skS.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkSBytes = pkS.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skS", skSBytes);
        PrintBytes("pkS", pkSBytes);
        Console.WriteLine();

        Console.WriteLine("=== 3) Sender generates ephemeral key pair (skE, enc) ===");
        /*
         * skE/pkE = sender ephemeral key.
         * enc is the serialized public key representation of skE.PublicKey.
         * RFC 9180 uses "enc" as the KEM output.
         */
        using var skE = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkE = skE.PublicKey!;
        byte[] skEBytes = skE.Export(KeyBlobFormat.RawPrivateKey);
        byte[] enc = pkE.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skE", skEBytes);
        PrintBytes("enc", enc);
        Console.WriteLine();

        Console.WriteLine("=== 4) Sender computes dh1, dh2, derives shared_secret via DHKEM Auth ===");
        /*
         * RFC 9180, DHKEM Auth (Encap/Decap in Auth mode):
         * - dh1 = DH(skE, pkR)
         * - dh2 = DH(skS, pkR)
         * - dh  = dh1 || dh2  (this exact order)
         */
        SharedSecret? senderDh1Secret = KeyAgreementAlgorithm.X25519.Agree(skE, pkR, in ssParams);
        SharedSecret? senderDh2Secret = KeyAgreementAlgorithm.X25519.Agree(skS, pkR, in ssParams);
        if (senderDh1Secret is null || senderDh2Secret is null)
        {
            throw new InvalidOperationException("Sender DH failed.");
        }

        using var senderDh1 = senderDh1Secret;
        using var senderDh2 = senderDh2Secret;
        byte[] dh1 = senderDh1.Export(SharedSecretBlobFormat.RawSharedSecret);
        byte[] dh2 = senderDh2.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh1 = DH(skE, pkR)", dh1);
        PrintBytes("dh2 = DH(skS, pkR)", dh2);

        /*
         * RFC 9180, Section 4.1 (ExtractAndExpand):
         * eae_prk       = LabeledExtract("", "eae_prk", dh)
         * kem_context   = enc || pkR || pkS   (Auth mode)
         * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
         */
        byte[] sharedSecretSender = KemExtractAndExpandAuth(dh1, dh2, enc, pkRBytes, pkSBytes, kemSuiteId);
        PrintBytes("shared_secret", sharedSecretSender);
        Console.WriteLine();

        Console.WriteLine("=== 5) Sender runs KeySchedule(mode=0x02) => aead_key, aead_nonce ===");
        /*
         * RFC 9180, Section 5.1 (Key Schedule):
         * - psk = empty, psk_id = empty (no PSK in this demo)
         * - mode = 0x02
         */
        var senderKs = KeySchedule(ModeAuth, sharedSecretSender, info, suiteId, Nk, Nn);
        PrintBytes("aead_key", senderKs.aeadKey);
        PrintBytes("aead_nonce", senderKs.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 6) Sender encrypts with AES-256-GCM and outputs sealed = enc || ciphertext_with_tag ===");
        string plaintext = "Hello HPKE Auth mode";
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        PrintBytes("plaintext", plaintextBytes);

        // Import AEAD key from key schedule (RawSymmetricKey)
        using var aeadKeySender = Key.Import(AeadAlgorithm.Aes256Gcm, senderKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);

        // ciphertext_with_tag: NSec returns ciphertext + 16-byte GCM tag together.
        byte[] ciphertextWithTag = AeadAlgorithm.Aes256Gcm.Encrypt(aeadKeySender, senderKs.aeadNonce, aad, plaintextBytes);
        PrintBytes("ciphertext_with_tag", ciphertextWithTag);

        /*
         * Message format required by the task:
         * sealed = enc || ciphertext_with_tag
         * Nonce is NOT transmitted (it is deterministically derived).
         */
        byte[] sealedMessage = Concat(enc, ciphertextWithTag);
        PrintBytes("sealed = enc || ciphertext_with_tag", sealedMessage);
        Console.WriteLine();

        Console.WriteLine("=== 7) Receiver derives shared_secret via DHKEM Auth using skR, enc, pkS ===");
        // Receiver reconstructs the ephemeral public key from enc.
        PublicKey encPublic = PublicKey.Import(KeyAgreementAlgorithm.X25519, enc, KeyBlobFormat.RawPublicKey);

        /*
         * RFC 9180, DHKEM Auth Decap:
         * - dh1 = DH(skR, enc)
         * - dh2 = DH(skR, pkS)
         * - dh  = dh1 || dh2 (same order as sender)
         */
        SharedSecret? receiverDh1Secret = KeyAgreementAlgorithm.X25519.Agree(skR, encPublic, in ssParams);
        SharedSecret? receiverDh2Secret = KeyAgreementAlgorithm.X25519.Agree(skR, pkS, in ssParams);
        if (receiverDh1Secret is null || receiverDh2Secret is null)
        {
            throw new InvalidOperationException("Receiver DH failed.");
        }

        using var receiverDh1 = receiverDh1Secret;
        using var receiverDh2 = receiverDh2Secret;
        byte[] rDh1 = receiverDh1.Export(SharedSecretBlobFormat.RawSharedSecret);
        byte[] rDh2 = receiverDh2.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh1 = DH(skR, enc)", rDh1);
        PrintBytes("dh2 = DH(skR, pkS)", rDh2);

        byte[] sharedSecretReceiver = KemExtractAndExpandAuth(rDh1, rDh2, enc, pkRBytes, pkSBytes, kemSuiteId);
        PrintBytes("shared_secret", sharedSecretReceiver);
        Console.WriteLine();

        Console.WriteLine("=== 8) Receiver runs KeySchedule(mode=0x02) and decrypts ===");
        var receiverKs = KeySchedule(ModeAuth, sharedSecretReceiver, info, suiteId, Nk, Nn);
        PrintBytes("aead_key", receiverKs.aeadKey);
        PrintBytes("aead_nonce", receiverKs.aeadNonce);

        using var aeadKeyReceiver = Key.Import(AeadAlgorithm.Aes256Gcm, receiverKs.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[]? recovered = AeadAlgorithm.Aes256Gcm.Decrypt(aeadKeyReceiver, receiverKs.aeadNonce, aad, ciphertextWithTag);
        if (recovered is null)
        {
            throw new InvalidOperationException("Decryption failed.");
        }

        Console.WriteLine();
        Console.WriteLine("=== 9) Print recovered plaintext and verify it matches ===");
        PrintBytes("recovered_plaintext", recovered);
        string recoveredText = Encoding.UTF8.GetString(recovered);
        Console.WriteLine("recovered utf8: " + recoveredText);
        Console.WriteLine("match: " + (recoveredText == plaintext));
    }

    private static (byte[] aeadKey, byte[] aeadNonce) KeySchedule(byte mode, byte[] sharedSecret, byte[] info, byte[] suiteId, int nk, int nn)
    {
        /*
         * RFC 9180, Section 5.1: KeySchedule(mode, shared_secret, info, psk, psk_id)
         *
         * For this demo:
         * - psk = ""
         * - psk_id = ""
         *
         * psk_id_hash         = LabeledExtract("", "psk_id_hash", psk_id)
         * info_hash           = LabeledExtract("", "info_hash", info)
         * key_schedule_context= mode || psk_id_hash || info_hash
         * secret              = LabeledExtract(shared_secret, "secret", psk)
         * key                 = LabeledExpand(secret, "key", key_schedule_context, Nk)
         * base_nonce          = LabeledExpand(secret, "nonce", key_schedule_context, Nn)
         */
        byte[] empty = Array.Empty<byte>();
        byte[] pskIdHash = LabeledExtract(empty, "psk_id_hash", empty, suiteId);
        byte[] infoHash = LabeledExtract(empty, "info_hash", info, suiteId);
        byte[] keyScheduleContext = Concat(new[] { mode }, pskIdHash, infoHash);

        byte[] secret = LabeledExtract(sharedSecret, "secret", empty, suiteId);
        byte[] aeadKey = LabeledExpand(secret, "key", keyScheduleContext, nk, suiteId);
        byte[] aeadNonce = LabeledExpand(secret, "nonce", keyScheduleContext, nn, suiteId);
        return (aeadKey, aeadNonce);
    }

    private static byte[] KemExtractAndExpandAuth(byte[] dh1, byte[] dh2, byte[] enc, byte[] pkR, byte[] pkS, byte[] kemSuiteId)
    {
        /*
         * RFC 9180, Section 4.1 + Auth mode KEM context:
         *
         * dh = dh1 || dh2
         * eae_prk = LabeledExtract("", "eae_prk", dh)
         * kem_context = enc || pkRm || pkSm  (here: pkR, pkS as RawPublicKey)
         * Nsecret = Nh (for HKDF-SHA256 = 32)
         * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
         */
        byte[] dh = Concat(dh1, dh2);
        byte[] empty = Array.Empty<byte>();
        byte[] eaePrk = LabeledExtract(empty, "eae_prk", dh, kemSuiteId);
        byte[] kemContext = Concat(enc, pkR, pkS);
        int nSecret = new HkdfSha256().PseudorandomKeySize;
        return LabeledExpand(eaePrk, "shared_secret", kemContext, nSecret, kemSuiteId);
    }

    private static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm, byte[] suiteId)
    {
        /*
         * RFC 9180, Section 4: LabeledExtract
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
         * RFC 9180, Section 4: LabeledExpand
         * LabeledExpand(prk, label, info, L) =
         *   HKDF-Expand(prk, I2OSP(L,2) || "HPKE-v1" || suite_id || label || info, L)
         */
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
        /*
         * RFC 5869 HKDF-Extract:
         * If salt is empty, a HashLen all-zero salt is used (32 here for SHA-256).
         */
        byte[] actualSalt = salt.Length == 0 ? new byte[32] : salt;
        var hkdf = new HkdfSha256();
        return hkdf.Extract(ikm, actualSalt);
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        // RFC 5869 HKDF-Expand
        var hkdf = new HkdfSha256();
        return hkdf.Expand(prk, info, length);
    }

    private static byte[] I2osp2(ushort value)
    {
        /* RFC 8017 I2OSP (2-byte big-endian variant used for HPKE IDs/lengths here). */
        return new[] { (byte)(value >> 8), (byte)(value & 0xFF) };
    }

    private static byte[] Concat(params byte[][] parts)
    {
        // Helper function: concatenates byte arrays exactly in the provided order.
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
        // Uniform output format: label + length + hex.
        Console.WriteLine($"{label} ({value.Length} bytes): {HexEncode(value)}");
    }

    private static string HexEncode(byte[] value)
    {
        // Lowercase hex format for consistent demo logs.
        var sb = new StringBuilder(value.Length * 2);
        foreach (byte b in value)
        {
            sb.Append(b.ToString("x2"));
        }

        return sb.ToString();
    }
}
