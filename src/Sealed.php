<?php

namespace Io\Auth;

use Data\Postgres;
use Io\Attributes\Inject;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Credentials that travel through an app which must not read them: a game server or a shop offers the sign-in
 * form, the browser seals the password for the site that keeps the accounts, the app passes it on.
 *
 * The browser asks for challenge() (through the app), seals with js/seal.js: an ephemeral ECDH P-256 key, the
 * shared secret through HKDF-SHA256 (salt: the challenge, info: "io-auth-seal") into an AES-256-GCM key, the
 * challenge as additional data. open() takes each challenge once, so a sealed message can't be sent twice.
 */
final class Sealed
{
    /** SubjectPublicKeyInfo of a P-256 key up to its point: the DER a raw point needs to become a PEM */
    private const string SPKI_P256 = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    #[Inject]
    private Postgres $db;

    #[Inject]
    private AuthOptions $options;

    private ?OpenSSLAsymmetricKey $key = null;

    /** @return array{key: string, challenge: string} the public key (raw P-256 point) and a fresh challenge, base64url */
    public function challenge(): array
    {
        $challenge = random_bytes(32);
        $this->db->execute('DELETE FROM auth_challenges WHERE expires_at < now()');
        $this->db->execute(
            "INSERT INTO auth_challenges (challenge_hash, expires_at) VALUES ($1, now() + interval '1 second' * $2)",
            [hash('sha256', $challenge), $this->options->sealChallenge],
        );

        return ['key' => self::base64($this->publicPoint()), 'challenge' => self::base64($challenge)];
    }

    /**
     * The sealed text, or null: unknown, expired or used challenge, a foreign key, tampered data. Each challenge
     * counts once, also when opening fails.
     *
     * @param string $challenge from challenge()
     * @param string $key       the browser's ephemeral public key, raw point
     * @param string $iv        12 bytes
     * @param string $data      ciphertext with the 16-byte tag at its end; all four base64url
     */
    public function open(string $challenge, string $key, string $iv, string $data): ?string
    {
        $challenge = self::unbase64($challenge);
        $point = self::unbase64($key);
        $iv = self::unbase64($iv);
        $data = self::unbase64($data);
        if ($challenge === null || $point === null || strlen($point) !== 65 || $iv === null || strlen($iv) !== 12 || $data === null || strlen($data) < 17) {
            return null;
        }
        $taken = $this->db->execute('DELETE FROM auth_challenges WHERE challenge_hash = $1 AND expires_at > now()', [hash('sha256', $challenge)]);
        if ($taken !== 1) {
            return null;
        }
        $peer = openssl_pkey_get_public(self::pem($point));
        $shared = $peer === false ? false : openssl_pkey_derive($peer, $this->privateKey());
        if ($shared === false) {
            return null;
        }
        $aes = hash_hkdf('sha256', $shared, 32, 'io-auth-seal', $challenge);
        $plain = openssl_decrypt(substr($data, 0, -16), 'aes-256-gcm', $aes, OPENSSL_RAW_DATA, $iv, substr($data, -16), $challenge);

        return $plain === false ? null : $plain;
    }

    /** The key of AuthOptions::$sealKeyFile, made on first use; a worker that comes second reads the first one's */
    private function privateKey(): OpenSSLAsymmetricKey
    {
        if ($this->key !== null) {
            return $this->key;
        }
        $file = $this->options->sealKeyFile;
        if ($file === '') {
            throw new RuntimeException('Sealed needs AuthOptions::$sealKeyFile');
        }
        if (!is_file($file)) {
            $new = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            if ($new === false || !openssl_pkey_export($new, $pem) || !is_string($pem)) {
                throw new RuntimeException('Sealed could not create a key');
            }
            // x: only one writer wins; the others read its key below
            $handle = @fopen($file, 'x');
            if ($handle !== false) {
                chmod($file, 0600);
                fwrite($handle, $pem);
                fclose($handle);
            }
        }
        $key = openssl_pkey_get_private((string) file_get_contents($file));
        if ($key === false) {
            throw new RuntimeException("Sealed could not read its key in $file");
        }

        return $this->key = $key;
    }

    private function publicPoint(): string
    {
        $details = openssl_pkey_get_details($this->privateKey());
        $ec = is_array($details) && is_array($details['ec'] ?? null) ? $details['ec'] : [];
        $x = is_string($ec['x'] ?? null) ? $ec['x'] : '';
        $y = is_string($ec['y'] ?? null) ? $ec['y'] : '';

        return "\x04" . str_pad($x, 32, "\0", STR_PAD_LEFT) . str_pad($y, 32, "\0", STR_PAD_LEFT);
    }

    private static function pem(string $point): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode((string) hex2bin(self::SPKI_P256) . $point), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function base64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function unbase64(string $text): ?string
    {
        $bytes = base64_decode(strtr($text, '-_', '+/'), true);

        return $bytes === false || $bytes === '' ? null : $bytes;
    }
}
