@echo off
echo /************************************************** > libVES.js
echo .* This is a working build created by Makefile.bat. >> libVES.js
echo .* Use Makefile.pl to generate a complete build >> libVES.js
echo .**************************************************/ >> libVES.js
type libVES-base.js libVES.Util.js libVES.Math.js libVES.Object.js libVES.Algo.js libVES.Cipher.js libVES.Scramble.js libVES.Recovery.js libVES.Delegate.js libVES.Flow.js libVES.Auth.js libVES.Algo.OQS.js >> libVES.js
