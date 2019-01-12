# HeapHop

Introduction to HeapHop:
HeapHop is a Memory leak detector for windows 32-bit executables.
Made by Michael Cohen & Zvei Eliezer Nir, 2019.
This project was part of our "fundamentales in Software Security" course
under the instruction of Arie Haenel.
We used Tsuda Kageyu's "MinHook" library for the implementation of the hooking part, and we owe him a credit.
Please look at his repsitory: https://github.com/TsudaKageyu/minhook

Compiling HeapHop:
You must compile the solution in "Debug" mode. Otherwise all functionality of "DbgHelp" library is disabled.

Using HeapHop:
If you use are using the release directory, just open cmd at the directory path.
Else if you compiled by yourself, open cmd at "HeapHop\Debug" directory.
Now type the following command:

` > HeapHop.exe myTarget.exe`
` > type log.txt`

The first command is to use HeapHop. If the target needs some aregument, put them right after "myTarget.exe".
The second command is to print the log file.

That's it for now.
