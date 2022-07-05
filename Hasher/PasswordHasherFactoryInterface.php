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

interface PasswordHasherFactoryInterface
{
    /**
     * Build a new password hasher.
     *
     * @param string $desiredHasher The password hasher to use.
     * @param array  $options       A list of options for the password hasher.
     *
     * @return \Vixel\Hasher\PasswordHasherFactoryInterface Return the password hasher factory.
     */
    public function buildHasher(string $desiredHasher, array $options = []): PasswordHasherFactoryInterface;
}
