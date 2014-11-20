<?php
/* 
   Use of this file is subject to the "BSD-3-clause" license, the full
   text of which can be found in the file 'LICENSE' in this directory,
   or at http://opensource.org/licenses/BSD-3-Clause

   Copyright (c) 2014, Massachusetts Institute of Technology
*/

require('Crypt/RSA.php');

/**
 * A base exception class for this module.
 */
class JWTException extends Exception {
}

/**
 * A thin wrapper around curl for convenience.
 * 
 */
function _curl_get($uri, $want_json=true) {
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $uri);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
  $result = curl_exec($ch);
  if ($errno = curl_errno($ch)) {
    $msg = "curl failed: " . curl_strerror($errno);
    // Probably not necessary, but doesn't hurt to close the handle
    // before we throw the exception
    curl_close($ch);
    throw new JWTException($msg);
  }
  curl_close($ch);
  if ($want_json) {
    $result = json_decode($result);
    if (is_null($result)) {
      throw new JWTException("Failed to decode JSON from $uri");
    }
  }
  return $result;
}

/**
 * Decode base64url-encoded things.
 */
function base64url_decode($base64url) {
  return base64_decode(b64url2b64($base64url));
}

/**
 * Per RFC4648, "base64 encoding with URL-safe and filename-safe
 * alphabet".  This just replaces characters 62 and 63.  None of the
 * reference implementations seem to restore the padding if necessary,
 * but we'll do it anyway.
 *
 */
function b64url2b64($base64url) {
  // "Shouldn't" be necessary, but why not
  $padding = strlen($base64url) % 4;
  if ($padding > 0) {
    $base64url .= str_repeat("=", 4 - $padding);
  }
  return strtr($base64url, '-_', '+/');
}

/**
 * A representation of a Java Web Token.
 *
 * Example:
 *   $jwt = new JWT("...");
 *   if (! $jwt->verify()) {
 *     echo "JWT verification failed: " . $jwt->verify_error;
 *   } else {
 *     echo "Verification succeeded.";
 *   }
 */
class JWT {
  private static $sep = '.';

  /**
   * The token's header
   */
  public $header = '';
  /**
   * The token's body
   */
  public $body = '';
  /**
   * The token's signature to be verified
   */
  public $signature = '';

  private $tokenparts;

  /**
   * Details of why verification failed.
   */
  public $verify_error = NULL;

  /**
   * Parse a raw id_token
   */
  function __construct($token) {
    $this->tokenparts = explode(self::$sep, $token);
    if (count($this->tokenparts) != 3) {
      throw new JWTException("Not a JWS-encoded token");
    }
    $this->header = json_decode(base64url_decode($this->tokenparts[0]));
    $this->body = json_decode(base64url_decode($this->tokenparts[1]));
    $this->signature = base64url_decode($this->tokenparts[2]);
  }

  /**
   * Verify a token and return true if verification succeeded.
   * Signature verification currently limited to RSA only.
   */
  function verify() {
    if (! $this->verify_signature()) {
      $this->verify_error = "Failed to verify signature.";
      return false;
    }
    $now = time();
    if ($this->body->exp < $now) {
      $this->verify_error = "Token has expired.";
      return false;
    }
    if ($this->body->iat > $now) {
      $this->verify_error = "Token was issued in the future.";
      return false;
    }
    return true;
  }

  /**
   * Check if the given client ID is in the audience for this token.
   */
  function audience_for($client_id) {
    return in_array($client_id, $this->body->aud, true);
  }

  /**
   * Verify the token's signature.
   */
  function verify_signature() {
    switch ($this->header->alg) {
    case 'RS256':
    case 'RS384':
    case 'RS512':
      $keytype = 'RSA';
      break;
    default:
      throw new JWTException('Can only verify RSA signatures');
    }
    // Should we allow http:// URIs?
    // Avoid double-slash issues
    $uri = "https://" .
      parse_url($this->body->iss, PHP_URL_HOST) .
      "/.well-known/openid-configuration";
    $openid_config = _curl_get($uri);
    $jwk = _curl_get($openid_config->jwks_uri);
    foreach($jwk->keys as $key) {
      if ($key->kty == $keytype) {
	return $this->verify_rsa_signature($key);
      }
    }
    throw new JWTException('Could not find key to use');
  }

  /**
   * Verify the RSA signature of a token
   */
  private function verify_rsa_signature($key) {
    if (!(property_exists($key, 'n') and property_exists($key, 'e'))) {
      throw new JWTException('Bad key object');
    }
    // Since we already have base64url, we cheat and re-encode as base64
    // and shove it in XML
    $public_key_xml = "<RSAKeyValue>\r\n".
      "  <Modulus>" . b64url2b64($key->n) . "</Modulus>\r\n" . 
      "  <Exponent>" . b64url2b64($key->e) . "</Exponent>\r\n" . 
      "</RSAKeyValue>";
    $hashtype = 'sha' . substr($this->header->alg, 2);
    $rsa = new Crypt_RSA();
    $rsa->setHash($hashtype);
    $rsa->loadKey($public_key_xml, CRYPT_RSA_PUBLIC_FORMAT_XML);
    // PKCS1.5, despite the constant name
    $rsa->signatureMode = CRYPT_RSA_SIGNATURE_PKCS1;
    return $rsa->verify($this->tokenparts[0] .
			self::$sep .
			$this->tokenparts[1],
			$this->signature);
  }

}