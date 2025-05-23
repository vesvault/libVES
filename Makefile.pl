#!/usr/bin/perl
#/***************************************************************************
# *          ___       ___
# *         /   \     /   \    VESvault
# *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
# *            \\     //                   https://vesvault.com https://ves.host
# *             \\   //
# *     ___      \\_//
# *    /   \     /   \         libVES:                      VESvault API library
# *    \__ /     \ __/
# *       \\     //
# *        \\   //
# *         \\_//              - Key Management and Exchange
# *         /   \              - Item Encryption and Sharing
# *         \___/              - VESrecovery (TM)
# *
# *
# * (c) 2018 VESvault Corp
# * Jim Zubov <jz@vesvault.com>
# *
# * GNU General Public License v3
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
# *
# ***************************************************************************/

@Src = ('libVES-base.js','libVES.Util.js','libVES.Math.js','libVES.Object.js','libVES.Algo.js','libVES.Cipher.js','libVES.Scramble.js','libVES.Recovery.js','libVES.Delegate.js','libVES.Flow.js', 'libVES.Auth.js', 'libVES.Algo.OQS.js', 'libVES.Watch.js', 'libVES.Vault.js', 'libVES.Item.js');

open VER,'VERSION';
chomp($Version = <VER>);
close VER;

$Dst = "libVES-$Version.js";
$DstMin = "libVES-$Version.min.js";
$DstNode = "libVES-$Version.node.js";
$result = '';

for (@Src) {
    open(SRC,$_) || die "Failed to read from $_";
    while (<SRC>) {
	s/^\s*\/\/.*//s;
	s/\r//s;
	$result .= $_;
    }
    close SRC;
}

$result =~s/\/\*.*?\*\///sg;

$Head = <<HEAD;
/***************************************************************************
 *          ___       ___
 *         /   \\     /   \\    VESvault
 *         \\__ /     \\ __/    Encrypt Everything without fear of losing the Key
 *            \\\\     //                   https://vesvault.com https://ves.host
 *             \\\\   //
 *     ___      \\\\_//
 *    /   \\     /   \\         libVES:                      VESvault API library
 *    \\__ /     \\ __/
 *       \\\\     //
 *        \\\\   //
 *         \\\\_//              - Key Management and Exchange
 *         /   \\              - Item Encryption and Sharing
 *         \\___/              - VESrecovery (TM)
 *
 *
 * (c) 2017 - 2022 VESvault Corp
 * Jim Zubov <jz\@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * \@title libVES
 * \@dev A JavaScript end-to-end encryption interface to VESvault REST API
 * \@version $Version
 *
 * \@dev Official source code: https://github.com/vesvault/libVES
 *
 * \@author Jim Zubov <jz\@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/
HEAD

open(DST,">$Dst") || die "Failed to write to $Dst";
print DST $Head;
print DST $result;
print DST "libVES.version = '$Version';\n";
close(DST) || die "Failed to write to $Dst";

open(DST,">$DstNode") || die "Failed to write to $DstNode";
print DST $Head;
print DST "crypto = require('crypto');\n";
print DST "crypto.subtle = require('subtle');\n";
print DST "XMLHttpRequest = require('xhr2');\n";
print DST $result;
print DST "libVES.version = '$Version';\n";
print DST "\nmodule.exports = libVES;\n";
close(DST) || die "Failed to write to $DstNode";

#`curl --data-urlencode input\@$Dst https://javascript-minifier.com/raw > $DstMin`;
