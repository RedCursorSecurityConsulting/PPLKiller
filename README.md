# PPLKiller
Tool to bypass LSA Protection (aka Protected Process Light)

I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.

# Usage and Demo
1. Open PPLKiller.sln wiht Visual Studio 2019 and build a Release binary which will be saved in PPLKiller\x64\Release\PPLKiller.exe
2. Place the RTCore64.sys (see below) into the same folder as the PPLKiller.exe executable. 

# Getting the Driver
Download it [HERE](https://mega.nz/file/BOwWEQjR#7bJqbrL_v-Wzy1ZaL_V4pR_sBDQQyuMddfoMF_ypbDU)
OR
1. Install 7-Zip if you dont already have it
2. Download and extract MSIAfterburnerSetup462Beta2.exe from http://download-eu2.guru3d.com/afterburner/[Guru3D.com]-MSIAfterburnerSetup462Beta2.zip
3. Right-click MSIAfterburnerSetup462Beta2.exe and chose "Open archive"
4. Select "RTCore64.sys" and chose Extract in the top menu
5. Put THIS file in the same directory as PPLKiller.exe

# Tool Usage
You'll always want to run `PPLKiller.exe /installDriver` first, and then an attack like `PPLKiller.exe /disableLSAProtection` and lastly cleanup with `PPLKiller.exe /uninstallDriver`

# Vidoe Usage
[![Bypassing LSA Protection](http://img.youtube.com/vi/w2_KqnhgN94/0.jpg)](http://www.youtube.com/watch?v=w2_KqnhgN94 "Bypassing LSA Protection")
