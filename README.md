# SplashHack

_Client-side patches for SEGA SPLASH! GOLF_

---

⚠ This project is not affiliated with or endorsed by SEGA.

---

## What's this?

Fixes a number of issues in version 0.956 of this ancient game:

- Use modern OpenSSL
- Disable GameGuard entirely
- Fix the text encoding issues on non-Japanese Windows systems
  - stops the game from crashing on launch
  - fixes `key.cfg` (keybindings) not being read/written properly
- Fix a bug with parsing the ChrMotionSE tables
  - fixes a crash when Rusk turns left while wielding an iron
- Allow the game to easily connect to a custom server
  - create a file called `server.txt` containing the IP address or hostname

For more background info, see my series of writeups about this game:

- **Part 1**: [They Made A Golf MMO With Sonic In it (Real!) (Not Clickbait!) (Only A Bit)](https://wuffs.org/blog/reviving-sega-splash-golf)
- **Part 2**: [Reviving Sega's forgotten golf MMO after 14 years](https://wuffs.org/blog/reviving-sega-splash-golf-part-2)
- **Part 3**: _(to be published)_

SplashHack supplies replacement OpenSSL DLL files which serve two purposes: simulating the functions that the game expects to load from its ancient version, **and** patching other parts of the game as soon as it launches.

You'll also probably want to use _SplashDecrypt_ to turn `Splash.bin` into an EXE file that you can run, without needing to go through the broken launcher.

---

## How To Build

### Obtaining OpenSSL

SplashHack uses OpenSSL 3.1.2, but should work with newer versions unless things change drastically.

Download the **OpenSSL ZIP File** from here: https://kb.firedaemon.com/support/solutions/articles/4000121705

Extract it into the repository root, such that you should have the following files (among others):

- `openssl-3/x86/include/openssl/crypto.h`
- `openssl-3/x86/lib/libcrypto.lib`

### Obtaining MinHook

SplashHack uses MinHook to hook functions in the game, and one Windows API function.

Download **MinHook_133_lib.zip** from here: https://github.com/TsudaKageyu/minhook/releases

Extract it into `minhook/` in the repository root, such that you should have the following files (among others):

- `minhook/include/MinHook.h`
- `minhook/lib/libMinHook-x86-v141-mt.lib`

### Compiling

I used Visual Studio 2019 with the Windows XP toolset (known as `v141_xp`) installed. Newer versions of VS should work if they provide the same toolset, but I haven't tested this. (You'll need to recompile MinHook to use any newer compilers.)

Building the solution will produce `libeay32.dll` and `ssleay32.dll`. Replace the original game's DLLs with these two, and then include the two DLLs provided in `openssl-3/x86/bin`.
