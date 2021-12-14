# PPLKiller
Tool to bypass LSA Protection (aka Protected Process Light)

I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.

This https://github.com/wavestone-cdt/EDRSandblast does the same thing and is probably better. This https://github.com/itm4n/PPLdump does the same thing without using a driver.

# Usage and Demo
1. Open PPLKiller.sln with Visual Studio 2019 and build a Release binary which will be saved in PPLKiller\x64\Release\PPLKiller.exe
2. You'll always want to run `PPLKiller.exe /installDriver` first to install the driver
3. Run an attack like `PPLKiller.exe /disableLSAProtection` 
4. Cleanup with `PPLKiller.exe /uninstallDriver`

# Video Usage
[![Bypassing LSA Protection](http://img.youtube.com/vi/w2_KqnhgN94/0.jpg)](http://www.youtube.com/watch?v=w2_KqnhgN94 "Bypassing LSA Protection")

# Mitigations
- Use Credential Guard which uses virtualization-based security. This would prevent PPLKiller and PPLdump.
- Use a Microsoft Defender Application Control kernel-mode code integrity policy to restrict which drivers can be loaded. The tool [PPLdump](https://github.com/itm4n/PPLdump), which can disable LSA Protection without loading a driver, could still be used.
