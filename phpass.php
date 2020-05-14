<?php

interface PasswordInterface {

  /**
   * Maximum password length.
   */
  const PASSWORD_MAX_LENGTH = 512;

  /**
   * Hash a password using a secure hash.
   *
   * @param string $password
   *   A plain-text password.
   *
   * @return string
   *   A string containing the hashed password, or FALSE on failure.
   */
  public function hash($password);

  /**
   * Check whether a plain text password matches a hashed password.
   *
   * @param string $password
   *   A plain-text password
   * @param string $hash
   *   A hashed password.
   *
   * @return bool
   *   TRUE if the password is valid, FALSE if not.
   */
  public function check($password, $hash);

  /**
   * Check whether a hashed password needs to be replaced with a new hash.
   *
   * This is typically called during the login process when the plain text
   * password is available. A new hash is needed when the desired iteration
   * count has changed by a modification of the password-service in the
   * dependency injection container or if the user's password hash was
   * generated in an update like user_update_7000() (see the Drupal 7
   * documentation).
   *
   * @param string $hash
   *   The existing hash to be checked.
   *
   * @return bool
   *   TRUE if the hash is outdated and needs rehash.
   */
  public function needsRehash($hash);

}




class PhpassHashedPassword implements PasswordInterface {

  /**
   * The minimum allowed log2 number of iterations for password stretching.
   */
  const MIN_HASH_COUNT = 7;

  /**
   * The maximum allowed log2 number of iterations for password stretching.
   */
  const MAX_HASH_COUNT = 30;

  /**
   * The expected (and maximum) number of characters in a hashed password.
   */
  const HASH_LENGTH = 55;

  /**
   * Returns a string for mapping an int to the corresponding base 64 character.
   */
  public static $ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  /**
   * Specifies the number of times the hashing function will be applied when
   * generating new password hashes. The number of times is calculated by
   * raising 2 to the power of the given value.
   */
  protected $countLog2;

  /**
   * Constructs a new password hashing instance.
   *
   * @param int $countLog2
   *   Password stretching iteration count. Specifies the number of times the
   *   hashing function will be applied when generating new password hashes.
   *   The number of times is calculated by raising 2 to the power of the given
   *   value.
   */
  function __construct($countLog2) {

    // Ensure that $countLog2 is within set bounds.
    $this->countLog2 = $this
      ->enforceLog2Boundaries($countLog2);
  }

  /**
   * Encodes bytes into printable base 64 using the *nix standard from crypt().
   *
   * @param string $input
   *   The string containing bytes to encode.
   * @param int $count
   *   The number of characters (bytes) to encode.
   *
   * @return string
   *   Encoded string.
   */
  protected function base64Encode($input, $count) {
    $output = '';
    $i = 0;
    do {
      $value = ord($input[$i++]);
      $output .= static::$ITOA64[$value & 0x3f];
      if ($i < $count) {
        $value |= ord($input[$i]) << 8;
      }
      $output .= static::$ITOA64[$value >> 6 & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      if ($i < $count) {
        $value |= ord($input[$i]) << 16;
      }
      $output .= static::$ITOA64[$value >> 12 & 0x3f];
      if ($i++ >= $count) {
        break;
      }
      $output .= static::$ITOA64[$value >> 18 & 0x3f];
    } while ($i < $count);
    
    echo "COUNT: " . $count . "\n";
    echo "OUTPUT: " . $output . "\n";
    
    return $output;
  }

  /**
   * Generates a random base 64-encoded salt prefixed with hash settings.
   *
   * Proper use of salts may defeat a number of attacks, including:
   *  - The ability to try candidate passwords against multiple hashes at once.
   *  - The ability to use pre-hashed lists of candidate passwords.
   *  - The ability to determine whether two users have the same (or different)
   *    password without actually having to guess one of the passwords.
   *
   * @return string
   *   A 12 character string containing the iteration count and a random salt.
   */
  protected function generateSalt() {
    $output = '$S$';

    // We encode the final log2 iteration count in base 64.
    $output .= static::$ITOA64[$this->countLog2];

    // 6 bytes is the standard salt for a portable phpass hash.
    $output .= $this
      ->base64Encode(Crypt::randomBytes(6), 6);

echo "generateSalt: " . $output . "\n";

    return $output;
  }

  /**
   * Ensures that $count_log2 is within set bounds.
   *
   * @param int $count_log2
   *   Integer that determines the number of iterations used in the hashing
   *   process. A larger value is more secure, but takes more time to complete.
   *
   * @return int
   *   Integer within set bounds that is closest to $count_log2.
   */
  protected function enforceLog2Boundaries($count_log2) {
    if ($count_log2 < static::MIN_HASH_COUNT) {
      return static::MIN_HASH_COUNT;
    }
    elseif ($count_log2 > static::MAX_HASH_COUNT) {
      return static::MAX_HASH_COUNT;
    }
    return (int) $count_log2;
  }

  /**
   * Hash a password using a secure stretched hash.
   *
   * By using a salt and repeated hashing the password is "stretched". Its
   * security is increased because it becomes much more computationally costly
   * for an attacker to try to break the hash by brute-force computation of the
   * hashes of a large number of plain-text words or strings to find a match.
   *
   * @param string $algo
   *   The string name of a hashing algorithm usable by hash(), like 'sha256'.
   * @param string $password
   *   Plain-text password up to 512 bytes (128 to 512 UTF-8 characters) to
   *   hash.
   * @param string $setting
   *   An existing hash or the output of $this->generateSalt(). Must be at least
   *   12 characters (the settings and salt).
   *
   * @return string
   *   A string containing the hashed password (and salt) or FALSE on failure.
   *   The return string will be truncated at HASH_LENGTH characters max.
   */
  protected function crypt($algo, $password, $setting) {

    // Prevent DoS attacks by refusing to hash large passwords.
    if (strlen($password) > PasswordInterface::PASSWORD_MAX_LENGTH) {
      return FALSE;
    }

    // The first 12 characters of an existing hash are its setting string.
    $setting = substr($setting, 0, 12);
    if ($setting[0] != '$' || $setting[2] != '$') {
      return FALSE;
    }
    $count_log2 = $this
      ->getCountLog2($setting);


    // Stored hashes may have been crypted with any iteration count. However we
    // do not allow applying the algorithm for unreasonable low and high values
    // respectively.
    if ($count_log2 != $this
      ->enforceLog2Boundaries($count_log2)) {
      return FALSE;
    }
    $salt = substr($setting, 4, 8);

    // Hashes must have an 8 character salt.
    if (strlen($salt) != 8) {
      return FALSE;
    }

    // Convert the base 2 logarithm into an integer.
    $count = 1 << $count_log2;

    // We rely on the hash() function being available in PHP 5.2+.
    $hash = hash($algo, $salt . $password, TRUE);

echo "HASH-LEN: " . strlen($hash) . "\n";

    do {
      $hash = hash($algo, $hash . $password, TRUE);
    } while (--$count);
    $len = strlen($hash);

    echo "len: " . $len . "\n";

    echo "setting: " . $setting . "\n";

    $output = $setting . $this
      ->base64Encode($hash, $len);

    // $this->base64Encode() of a 16 byte MD5 will always be 22 characters.
    // $this->base64Encode() of a 64 byte sha512 will always be 86 characters.
    $expected = 12 + ceil(8 * $len / 6);

    echo "expected: " . $expected . "\n";

    return strlen($output) == $expected ? substr($output, 0, static::HASH_LENGTH) : FALSE;
  }

  /**
   * Parses the log2 iteration count from a stored hash or setting string.
   *
   * @param string $setting
   *   An existing hash or the output of $this->generateSalt(). Must be at least
   *   12 characters (the settings and salt).
   *
   * @return int
   *   The log2 iteration count.
   */
  public function getCountLog2($setting) {
    return strpos(static::$ITOA64, $setting[3]);
  }

  /**
   * {@inheritdoc}
   */
  public function hash($password) {
    return $this
      ->crypt('sha512', $password, $this
      ->generateSalt());
  }

  /**
   * {@inheritdoc}
   */
  public function check($password, $hash) {
    if (substr($hash, 0, 2) == 'U$') {

      // This may be an updated password from user_update_7000(). Such hashes
      // have 'U' added as the first character and need an extra md5() (see the
      // Drupal 7 documentation).
      $stored_hash = substr($hash, 1);
      $password = md5($password);
    }
    else {
      $stored_hash = $hash;
    }
    $type = substr($stored_hash, 0, 3);
    switch ($type) {
      case '$S$':

        // A normal Drupal 7 password using sha512.
        $computed_hash = $this
          ->crypt('sha512', $password, $stored_hash);
        break;
      case '$H$':

      // phpBB3 uses "$H$" for the same thing as "$P$".
      case '$P$':

        // A phpass password generated using md5.  This is an
        // imported password or from an earlier Drupal version.
        $computed_hash = $this
          ->crypt('md5', $password, $stored_hash);
        break;
      default:
        return FALSE;
    }

    // Compare using hashEquals() instead of === to mitigate timing attacks.

echo "STORED HASH: " . $stored_hash . "\n";
echo "COMPUTED HASH: " . $computed_hash . "\n";


    return $computed_hash && Crypt::hashEquals($stored_hash, $computed_hash);
  }

  /**
   * {@inheritdoc}
   */
  public function needsRehash($hash) {

    // Check whether this was an updated password.
    if (substr($hash, 0, 3) != '$S$' || strlen($hash) != static::HASH_LENGTH) {
      return TRUE;
    }

    // Ensure that $count_log2 is within set bounds.
    $count_log2 = $this
      ->enforceLog2Boundaries($this->countLog2);

    // Check whether the iteration count used differs from the standard number.
    return $this
      ->getCountLog2($hash) !== $count_log2;
  }

}


/**
 * Class Crypt
 */
class Crypt {

  /**
   * Returns a string of highly randomized bytes (over the full 8-bit range).
   *
   * This function is better than simply calling mt_rand() or any other built-in
   * PHP function because it can return a long string of bytes (compared to < 4
   * bytes normally from mt_rand()) and uses the best available pseudo-random
   * source.
   *
   * In PHP 7 and up, this uses the built-in PHP function random_bytes().
   * In older PHP versions, this uses the random_bytes() function provided by
   * the random_compat library.
   *
   * @param int $count
   *   The number of characters (bytes) to return in the string.
   *
   * @return string
   *   A randomly generated string.
   */
  public static function randomBytes($count) {
    return random_bytes($count);
  }


  /**
   * Compares strings in constant time.
   *
   * @param string $known_string
   *   The expected string.
   * @param string $user_string
   *   The user supplied string to check.
   *
   * @return bool
   *   Returns TRUE when the two strings are equal, FALSE otherwise.
   */
  public static function hashEquals($known_string, $user_string) {
    if (function_exists('hash_equals')) {
      return hash_equals($known_string, $user_string);
    }
    else {

      // Backport of hash_equals() function from PHP 5.6
      // @see https://github.com/php/php-src/blob/PHP-5.6/ext/hash/hash.c#L739
      if (!is_string($known_string)) {
        trigger_error(sprintf("Expected known_string to be a string, %s given", gettype($known_string)), E_USER_WARNING);
        return FALSE;
      }
      if (!is_string($user_string)) {
        trigger_error(sprintf("Expected user_string to be a string, %s given", gettype($user_string)), E_USER_WARNING);
        return FALSE;
      }
      $known_len = strlen($known_string);
      if ($known_len !== strlen($user_string)) {
        return FALSE;
      }

      // This is security sensitive code. Do not optimize this for speed.
      $result = 0;
      for ($i = 0; $i < $known_len; $i++) {
        $result |= ord($known_string[$i]) ^ ord($user_string[$i]);
      }
      return $result === 0;
    }
  }

}



$passwordHasher = new PhpassHashedPassword(16);

/*
$hashedPassword = $passwordHasher->hash("blableblu");
echo "HASHED PASSWORD: " . $hashedPassword . "\n";
*/


$crypt = $passwordHasher->check("blableblu", '$S$EgeYoltRy0BbbjBZpwTJhxq2l4vqHAnIQ.sFBjrm7m5.KoFCJ/Wp');

if($crypt) {
    echo "CRYPT: " . $crypt . "\n";
}
else {
    echo "doesn't pass\n";
}



