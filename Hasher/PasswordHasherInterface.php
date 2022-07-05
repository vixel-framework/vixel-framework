<?php
/**
 * GNU Lesser General Public License v2.1.
 *
 * Copyright (c) 2022 Nicholas English
 *
 * Primarily used for software libraries, the GNU LGPL requires that derived works be licensed under the same
 * license, but works that only link to it do not fall under this restriction. There are two commonly used
 * versions of the GNU LGPL.
 *
 * @author <https://github.com/omatamix> Nicholas English
 */

namespace Vixel\Hasher;

/**
 * @see <https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length>
 */
interface PasswordHasherInterface
{
    /** @const MIN_RECOMMENDED_PW_LENGTH The recommended minimum password length. */
    const MIN_RECOMMENDED_PW_LENGTH = 8;

    /** @const MAX_PASSWORD_LENGTH The maximum password length. */
    const MAX_PW_LENGTH = 4065;

    /**
     * Compute a new hash.
     *
     * @param string $password The password to hash.
     *
     * @throws \InvalidArgumentException If the password suppied is too long.
     *
     * @return string Returns the hashed password.
     */
    public function compute(string $password): string;

    /**
     * Verify the password matches the hash provided.
     *
     * @param string $password The password check.
     * @param string $hash     The hash to check against.
     *
     * @return bool Returns true if the password matches the given hash else return false.
     */
    public function verify(string $password, string $hash): bool;

    /**
     * Determine if the hash needs a rehash.
     *
     * @param string $hash The hash to check.
     *
     * @return bool Returns true if the hash needs a rehash and false if not.
     */
    public function needsRehash(string $hash): bool;
}
