// Seals a text for io/auth's Sealed with WebCrypto: seal(await (await fetch(...challenge)).json(), text)
// returns { challenge, key, iv, data }, all base64url, for Sealed::open() on the server.

const encoder = new TextEncoder();

const toBase64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromBase64 = (text) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

export async function seal({ key, challenge }, text) {
  const salt = fromBase64(challenge);
  const server = await crypto.subtle.importKey('raw', fromBase64(key), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const own = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: server }, own.privateKey, 256);
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  const aes = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode('io-auth-seal') },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: salt }, aes, encoder.encode(text));
  return { challenge, key: toBase64(await crypto.subtle.exportKey('raw', own.publicKey)), iv: toBase64(iv), data: toBase64(data) };
}
