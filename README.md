# PPLKiller
Tool is bypass LSA Protection (aka Protected Process Light)

I’ve noticed there is a common misconception that LSA Protection prevents attacks that leverage SeDebug or Administrative privileges to extract credential material from memory, like Mimikatz. LSA Protection does NOT protect from these attacks, at best it makes them slightly more difficult as an extra step needs to be performed.

The driver file can be downlaoded here:
http://download-eu2.guru3d.com/afterburner/[Guru3D.com]-MSIAfterburnerSetup462Beta2.zip
You just need to extract RTCore64.sys from the installer using something like 7zip and place into in the same folder as the PPLKiller executable.
