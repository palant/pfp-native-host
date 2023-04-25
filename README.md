PfP Native Host
===============

This application provides access to a KeePass KDBX passwords database via the [native messaging protocol](https://developer.chrome.com/docs/apps/nativeMessaging/). In theory, it can be used by any browser extension. Some design choices probably make it unsuitable for anything other than the PfP: Pain-free Passwords extension however.

When run without command line parameters, it starts in configuration mode. In the first step, this allows selecting a passwords database to be used or creating a new one. Next step is configuring browser support so that the application is being used as native messaging host.

Limitations
-----------

This application is not meant to deal with large databases. It will not cache any data between requests but rather read/decrypt the file data on each request. Unless the file stores many file attachments this usually provides sufficient performance. This allows the database to be modified by other applications when PfP is not being used.

This application also does not attempt to somehow secure data in memory. Given that a browser extension cannot possibly protect passwords or keys in memory, this would be a waste of time. It’s questionable whether any other solution can secure your data in a compromised (e.g. malware-infected) environment, but this one definitely doesn’t.

Supported KeePass database formats
----------------------------------

Only KDBX 4.x databases are supported, not any of the older formats. Also, only Argon2 key derivation is supported, not the less secure AES-KDF.

Unsupported functionality
-------------------------

This application does not aim to use all the functionality of the KeePass database format. It rather attempts to left unsupported functionality unchanged. In particular, it does not at this point support password grouping. This means that existing passwords will be left in their respective groups even when modified, new passwords will always be added to the root group however.

At this point, recycle bin, change history, modification times and file attachments are also unsupported. Any existing information here will be left unchanged.

Additional functionality
------------------------

KeePass databases don’t usually support website aliases. So aliases are stored in an item named `PFP_ALIASES` under `<CustomData>`.

Added constrains
----------------

KeePass databases are generally very flexible and allow almost anything. While this application supports this, it will also enforce additional constrains on data it adds:

* No empty titles
* Password value is mandatory
* Only one entry per hostname/title combination

Full entry URL is ignored, only the hostname part is considered by this application.
