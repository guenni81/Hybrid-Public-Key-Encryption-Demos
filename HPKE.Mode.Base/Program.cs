using System;
using System.Text;
using NSec.Cryptography;

namespace HPKE.Mode.Base;

internal static class Program
{
    private static void Main()
    {
        /*
         * Demo safety notice:
         * This program prints private keys and shared secrets to the console.
         * Never do this in production systems.
         */
        Console.WriteLine("DEMO ONLY: printing private keys and secrets is insecure. Never do this in production.");
        Console.WriteLine();

        /*
         * RFC 9180 ciphersuite identifiers:
         * KEM = DHKEM(X25519, HKDF-SHA256)
         * KDF = HKDF-SHA256
         * AEAD = AES-256-GCM
         */
        const ushort KemId = 0x0020; // DHKEM(X25519, HKDF-SHA256)
        const ushort KdfId = 0x0001; // HKDF-SHA256
        const ushort AeadId = 0x0002; // AES-256-GCM
        const byte ModeBase = 0x00;
        const int Nk = 32;
        const int Nn = 12;

        /*
         * Application-provided context and AEAD associated data (AAD).
         * Both are empty in this minimal demo.
         */
        byte[] info = Array.Empty<byte>();
        byte[] aad = Array.Empty<byte>();

        /*
         * suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
         * Used as domain separation for labeled HKDF.
         */
        byte[] hpkeSuiteId = Concat(
            Encoding.ASCII.GetBytes("HPKE"),
            I2osp2(KemId),
            I2osp2(KdfId),
            I2osp2(AeadId));

        // KEM suite_id = "KEM" || I2OSP(kem_id,2)
        byte[] kemSuiteId = Concat(
            Encoding.ASCII.GetBytes("KEM"),
            I2osp2(KemId));

        /*
         * Allow plaintext export so we can print demo material.
         * This is for demonstration only.
         */
        var keyParams = new KeyCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        /*
         * Allow exporting the raw shared secret for the demo.
         * This is for demonstration only.
         */
        var ssParams = new SharedSecretCreationParameters
        {
            ExportPolicy = KeyExportPolicies.AllowPlaintextExport
        };

        Console.WriteLine("=== 1) Recipient static key pair (X25519) ===");
        /*
         * Receiver static key pair:
         * skR: receiver private key
         * pkR: receiver public key
         */
        using var skR = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkR = skR.PublicKey!;
        byte[] skRBytes = skR.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkRBytes = pkR.Export(KeyBlobFormat.RawPublicKey);
        PrintBytes("skR", skRBytes);
        PrintBytes("pkR", pkRBytes);
        Console.WriteLine();

        Console.WriteLine("=== 2) Sender ephemeral key pair (X25519) ===");
        /*
         * Sender ephemeral key pair:
         * skE: sender ephemeral private key
         * pkE: sender ephemeral public key
         * enc: serialized pkE (sent to receiver)
         */
        using var skE = Key.Create(KeyAgreementAlgorithm.X25519, in keyParams);
        PublicKey pkE = skE.PublicKey!;
        byte[] skEBytes = skE.Export(KeyBlobFormat.RawPrivateKey);
        byte[] pkEBytes = pkE.Export(KeyBlobFormat.RawPublicKey);
        byte[] enc = pkEBytes;
        PrintBytes("skE", skEBytes);
        PrintBytes("pkE (enc)", pkEBytes);
        Console.WriteLine();

        Console.WriteLine("=== 3) DH / shared secret ===");
        /*
         * DH shared secret:
         * Sender computes DH(skE, pkR)
         * Receiver computes DH(skR, enc)
         * Both must be identical.
         */
        SharedSecret? dhSender = KeyAgreementAlgorithm.X25519.Agree(skE, pkR, in ssParams);
        SharedSecret? dhReceiver = KeyAgreementAlgorithm.X25519.Agree(skR, pkE, in ssParams);
        if (dhSender is null || dhReceiver is null)
        {
            throw new InvalidOperationException("Key agreement failed.");
        }
        using var dhSenderDisp = dhSender;
        using var dhReceiverDisp = dhReceiver;
        byte[] dhSenderBytes = dhSenderDisp.Export(SharedSecretBlobFormat.RawSharedSecret);
        byte[] dhReceiverBytes = dhReceiverDisp.Export(SharedSecretBlobFormat.RawSharedSecret);
        PrintBytes("dh (sender)", dhSenderBytes);
        PrintBytes("dh (receiver)", dhReceiverBytes);
        Console.WriteLine();

        /*
         * KEM ExtractAndExpand (DHKEM):
         * shared_secret = LabeledExpand(
         *     LabeledExtract("", "eae_prk", dh),
         *     "shared_secret",
         *     kem_context = enc || pkR,
         *     Nsecret)
         */
        Console.WriteLine("=== 3b) KEM ExtractAndExpand ===");
        byte[] sharedSecretSender = KemExtractAndExpand(dhSenderBytes, enc, pkRBytes, kemSuiteId);
        byte[] sharedSecretReceiver = KemExtractAndExpand(dhReceiverBytes, enc, pkRBytes, kemSuiteId);
        PrintBytes("shared_secret (sender)", sharedSecretSender);
        PrintBytes("shared_secret (receiver)", sharedSecretReceiver);
        Console.WriteLine();

        Console.WriteLine("=== 4) HKDF key schedule outputs ===");
        /*
         * Base mode KeySchedule:
         * Produces the AEAD key and nonce from the shared secret and info.
         */
        var senderKeySchedule = KeyScheduleBase(ModeBase, sharedSecretSender, info, hpkeSuiteId, Nk, Nn);
        PrintBytes("aead_key (sender)", senderKeySchedule.aeadKey);
        PrintBytes("aead_nonce (sender)", senderKeySchedule.aeadNonce);
        Console.WriteLine();

        Console.WriteLine("=== 5) AEAD encryption ===");
        /*
         * Single-shot AEAD encryption with AES-256-GCM.
         * The nonce comes from the key schedule (not transmitted).
         */
        string plaintext = "Hello HPKE Base mode";
        byte[] ptBytes = Encoding.UTF8.GetBytes(plaintext);
        Console.WriteLine("plaintext (utf8): " + plaintext);
        PrintBytes("plaintext (hex)", ptBytes);

        /*
         * Import raw symmetric key bytes for the AEAD algorithm.
         * Encrypt the plaintext with empty AAD.
         */
        using var aeadKey = Key.Import(AeadAlgorithm.Aes256Gcm, senderKeySchedule.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[] ct = AeadAlgorithm.Aes256Gcm.Encrypt(aeadKey, senderKeySchedule.aeadNonce, aad, ptBytes);
        PrintBytes("ciphertext+tag", ct);
        /*
         * sealed = enc || ciphertext_with_tag
         * The nonce is implicit and not transmitted.
         */
        byte[] sealedMessage = Concat(enc, ct);
        PrintBytes("sealed = enc || ciphertext+tag", sealedMessage);
        Console.WriteLine();

        Console.WriteLine("=== 6) Receiver key schedule + decryption ===");
        /*
         * Receiver derives the same key/nonce and decrypts.
         * If the transcript matches, plaintext is recovered.
         */
        var receiverKeySchedule = KeyScheduleBase(ModeBase, sharedSecretReceiver, info, hpkeSuiteId, Nk, Nn);
        PrintBytes("aead_key (receiver)", receiverKeySchedule.aeadKey);
        PrintBytes("aead_nonce (receiver)", receiverKeySchedule.aeadNonce);

        using var aeadKeyR = Key.Import(AeadAlgorithm.Aes256Gcm, receiverKeySchedule.aeadKey, KeyBlobFormat.RawSymmetricKey, in keyParams);
        byte[]? recovered = AeadAlgorithm.Aes256Gcm.Decrypt(aeadKeyR, receiverKeySchedule.aeadNonce, aad, ct);
        if (recovered is null)
        {
            throw new InvalidOperationException("Decryption failed.");
        }
        Console.WriteLine("recovered plaintext: " + Encoding.UTF8.GetString(recovered));
    }

    private static (byte[] aeadKey, byte[] aeadNonce) KeyScheduleBase(byte mode, byte[] sharedSecret, byte[] info, byte[] suiteId, int Nk, int Nn)
    {
        /*
         * RFC 9180 KeySchedule (Base mode):
         * psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
         * info_hash   = LabeledExtract("", "info_hash", info)
         * context     = mode || psk_id_hash || info_hash
         * secret      = LabeledExtract(shared_secret, "secret", psk)
         * aead_key    = LabeledExpand(secret, "key",   context, Nk)
         * aead_nonce  = LabeledExpand(secret, "nonce", context, Nn)
         *
         * Here psk and psk_id are empty.
         */
        byte[] empty = Array.Empty<byte>();
        byte[] pskIdHash = LabeledExtract(empty, "psk_id_hash", empty, suiteId);
        byte[] infoHash = LabeledExtract(empty, "info_hash", info, suiteId);
        byte[] keyScheduleContext = Concat(new[] { mode }, pskIdHash, infoHash);
        byte[] secret = LabeledExtract(sharedSecret, "secret", empty, suiteId);
        byte[] aeadKey = LabeledExpand(secret, "key", keyScheduleContext, Nk, suiteId);
        byte[] aeadNonce = LabeledExpand(secret, "nonce", keyScheduleContext, Nn, suiteId);
        return (aeadKey, aeadNonce);
    }

    private static byte[] LabeledExtract(byte[] salt, string label, byte[] ikm, byte[] suiteId)
    {
        /*
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
         * HKDF-Extract with SHA-256.
         * If salt is empty, RFC 5869 uses HashLen zeros.
         */
        byte[] actualSalt = salt.Length == 0 ? new byte[32] : salt;
        var hkdf = new HkdfSha256();
        return hkdf.Extract(ikm, actualSalt);
    }

    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        /*
         * HKDF-Expand with SHA-256.
         */
        var hkdf = new HkdfSha256();
        return hkdf.Expand(prk, info, length);
    }

    private static byte[] KemExtractAndExpand(byte[] dh, byte[] enc, byte[] pkR, byte[] kemSuiteId)
    {
        /*
         * RFC 9180 DHKEM ExtractAndExpand:
         * eae_prk = LabeledExtract("", "eae_prk", dh)
         * kem_context = enc || pkR
         * shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
         *
         * For HKDF-SHA256, Nsecret = 32 (HashLen).
         */
        byte[] empty = Array.Empty<byte>();
        byte[] eaePrk = LabeledExtract(empty, "eae_prk", dh, kemSuiteId);
        byte[] kemContext = Concat(enc, pkR);
        int nSecret = new HkdfSha256().PseudorandomKeySize;
        return LabeledExpand(eaePrk, "shared_secret", kemContext, nSecret, kemSuiteId);
    }

    private static byte[] I2osp2(ushort value)
    {
        /*
         * I2OSP for 2-byte big-endian values.
         */
        return new[] { (byte)(value >> 8), (byte)(value & 0xFF) };
    }

    private static byte[] Concat(params byte[][] parts)
    {
        /*
         * Concatenate byte arrays in order.
         */
        int total = 0;
        foreach (byte[] p in parts)
        {
            total += p.Length;
        }

        byte[] result = new byte[total];
        int offset = 0;
        foreach (byte[] p in parts)
        {
            Buffer.BlockCopy(p, 0, result, offset, p.Length);
            offset += p.Length;
        }

        return result;
    }

    private static void PrintBytes(string label, byte[] bytes)
    {
        /*
         * Uniform hex formatting for console output.
         */
        Console.WriteLine($"{label} ({bytes.Length} bytes): {ToHex(bytes)}");
    }

    private static string ToHex(byte[] bytes)
    {
        /*
         * Lowercase hex encoder.
         */
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString();
    }
}
