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

use LengthException;
use Vixel\Generator\Generator;

trait PasswordGenerator
{
    use Generator;

    /**
     * Generate a new password.
     *
     * @param int $length The desired length of the string.
     *
     * @return string Returns the newly generated password.
     */
    public function generatePassword(int $length): string
    {
        if ($length <= PasswordHasherInterface::MIN_RECOMMENDED_PW_LENGTH) {
            throw new LengthException(sprintf('Length must be greater than %s', $length));
        }
        $this->generateRandomString($length);
    }
}
