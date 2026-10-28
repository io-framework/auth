<?php

namespace Io\Auth;

use chillerlan\QRCode\{QRCode, QROptions};
use chillerlan\QRCode\Output\QRMarkupSVG;

/** Time-based one-time passwords (RFC 6238) as authenticator apps compute them: SHA-1, 6 digits, 30 seconds. */
final class Totp
{
    private const string ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const int STEP = 30;

    /** A new secret: 160 random bits, base32 as apps expect it. */
    public static function secret(): string
    {
        return self::base32(random_bytes(20));
    }

    /** The URI a QR code carries: otpauth://totp/Issuer:account?secret=...&issuer=Issuer */
    public static function uri(string $secret, string $account, string $issuer): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($account)
            . '?' . http_build_query(['secret' => $secret, 'issuer' => $issuer], encoding_type: PHP_QUERY_RFC3986);
    }

    /** The QR code for an authenticator app, as an SVG data URI for an <img>. */
    public static function qr(string $secret, string $account, string $issuer): string
    {
        $qr = (new QRCode(new QROptions(['outputInterface' => QRMarkupSVG::class, 'outputBase64' => true])))->render(self::uri($secret, $account, $issuer));
        return is_string($qr) ? $qr : '';
    }

    public static function code(string $secret, int $step): string
    {
        $hash = hash_hmac('sha1', pack('J', $step), self::unbase32($secret), true);
        $offset = ord($hash[19]) & 0x0f;
        $unpacked = unpack('N', substr($hash, $offset, 4));
        $number = (is_array($unpacked) && is_int($unpacked[1] ?? null) ? $unpacked[1] : 0) & 0x7fffffff;
        return str_pad((string) ($number % 1_000_000), 6, '0', STR_PAD_LEFT);
    }

    /**
     * The step $code belongs to, one step of clock drift either way allowed; null if it matches none or a step at
     * or before $lastStep, so a code works only once.
     */
    public static function verify(string $secret, string $code, int $now, ?int $lastStep = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (preg_match('/^\d{6}$/', $code) !== 1) {
            return null;
        }
        $current = intdiv($now, self::STEP);
        foreach ([$current, $current - 1, $current + 1] as $step) {
            if (($lastStep === null || $step > $lastStep) && hash_equals(self::code($secret, $step), $code)) {
                return $step;
            }
        }
        return null;
    }

    private static function base32(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::ALPHABET[(int) bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    private static function unbase32(string $text): string
    {
        $bits = '';
        foreach (str_split(strtoupper(rtrim($text, '='))) as $char) {
            $value = strpos(self::ALPHABET, $char);
            if ($value !== false) {
                $bits .= str_pad(decbin($value), 5, '0', STR_PAD_LEFT);
            }
        }
        $bytes = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr((int) bindec($byte) & 0xff);
            }
        }
        return $bytes;
    }
}
