#!/usr/bin/perl

#/**
# * @title libVES Build Utility
# *
# * @author Jim Zubov <jz@vesvault.com> (VESvault)
# * GPL license, http://www.gnu.org/licenses/
# */

@Src = ('libVES-base.js','libVES.Util.js','libVES.Math.js','libVES.Object.js','libVES.Algo.js','libVES.Cipher.js','libVES.Scramble.js','libVES.Recovery.js','libVES.Delegate.js');

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
/**
 * \@title libVES
 * \@dev A JavaScript end-to-end encryption interface to VESvault REST API
 * \@version $Version
 *
 * \@dev Official source code: https://github.com/vesvault/libVES
 *
 * \@author Jim Zubov <jz\@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
HEAD

open(DST,">$Dst") || die "Failed to write to $Dst";
print DST $Head;
print DST $result;
close(DST) || die "Failed to write to $Dst";

open(DST,">$DstNode") || die "Failed to write to $DstNode";
print DST $Head;
print DST $result;
print DST "\nmodule.exports = libVES;\n";
close(DST) || die "Failed to write to $DstNode";

`curl --data-urlencode input\@$Dst https://javascript-minifier.com/raw > $DstMin`;
