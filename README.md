# PPLKiller
Tool to bypass LSA Protection (aka Protected Process Light)

I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.

# Usage and Demo
1. Open PPLKiller.sln wiht Visual Studio 2019 and build a Release binary which will be saved in PPLKiller\x64\Release\PPLKiller.exe
2. You'll always want to run `PPLKiller.exe /installDriver` first to install the driver
3. Run an attack like `PPLKiller.exe /disableLSAProtection` 
4. CLeanup with `PPLKiller.exe /uninstallDriver`

# Vidoe Usage
[![Bypassing LSA Protection](http://img.youtube.com/vi/w2_KqnhgN94/0.jpg)](http://www.youtube.com/watch?v=w2_KqnhgN94 "Bypassing LSA Protection")

# Other
I highly recommend checking https://github.com/itm4n/PPLdump. PPLdump can also disable LSA Protection without loading a driver and is probably more stealthy. 