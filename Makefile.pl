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

open(DST,">$Dst") || die "Failed to write to $Dst";
print DST <<'HEAD';
/**
 * @title libVES
 * @dev A JavaScript end-to-end encryption interface to VESvault REST API
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
HEAD
print DST $result;
close(DST) || die "Failed to write to $Dst";

`curl --data-urlencode input\@$Dst https://javascript-minifier.com/raw > $DstMin`;
