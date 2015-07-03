# OTRLib

Off The Record (OTR) messaging cryptography protocol
library in C# for Windows 8 Runtime. This was done
during the Facebook/Windows Hackathon to create
SecureChat for Facebook Windows 8 App.

## Install

Install the NuGet package "OTR" or via command line:

```sh
PM> Install-Package OTR
```

## What is OTR

* Confidentiality so that the messages are encrypted. 
* Authentication that verifies who the initiator and
  receiver are.
* Perfect Forward Secrecy so that each instant message
  sent is encrypted using a different encryption key.
* Deniability, so that the MAC keys that already have
  been used will not be used again.

## Development

This was developed by Code Project [Don Fizachi](http://www.codeproject.com/Articles/644318/Off-The-Record-OTR-Security-Protocol) originally for .NET.
We converted it to run on the Windows 8 Runtime. These
areas has changed:

* Windows 8 Runtime APIs do not support System.Security.Cryptography.
  The cryptography methods had to be rewritten using the
  Windows.Security.Cryptography methods.
* Exception handling had to change to support Windows
  Runtime
* Logging had to change
* Random Byte Generator had to change using different
  approach
 
## Demo App

Take a look at the Test folder, thats a demo app that sends OTR messages back and fourth to two clients. 
