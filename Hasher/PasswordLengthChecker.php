<?php
/**
 * GNU Lesser General Public License v2.1
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

use ParagonIE\ConstantTime\Binary;

trait PasswordLengthChecker
{
    /**
     * Check to see if a password is too long.
     *
     * @param string $password The user's password.
     *
     * @return bool Returns true if the password is too long
     *              else return false.
     */
    public function isPasswordTooLong(string $password): bool
    {
        return Binary::safeStrlen($password) > 4065;
    }
}
