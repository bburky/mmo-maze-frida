# Frida MMO Maze Agent

See https://lightbug14.gitbook.io/ for documentation on the character controller.

### How to compile & load

Perform the following in the same directory as Maze.exe from http://maze.liveoverflow.com/

```sh
$ git clone https://github.com/bburky/mmo-maze-frida
$ cd mmo-maze-frida/
$ npm install
$ ../Maze.exe -logfile log.txt ; frida --runtime=v8 --debug Maze.exe --load _agent.js
```

Or start the process directly with:

```
frida  --runtime=v8 --debug --file ../Maze.exe --load _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.


### Extract symbols

Symbols were extracted from the challenge binary using [Il2CppDumper](https://github.com/Perfare/Il2CppDumper). The output `script.json` and `il2cpp.h` files are in the [il2cpp](il2cpp) directory.

These symbols are imported by `maze.ts` and with helper functions `nativePointer(symbol)` and `nativeFunction(symbol)` to lookup symbols and create Frida objects. There's some rudimentary automatic parsing of arguments for use with Frida's `NativeFunction`.

I couldn't find a way to easily import a C header file with JavaScript, I used Ghidra to manually calculate offsets into structs. A definition of `size_t` was added to `il2cpp.h` to allow Ghidra to import it.
