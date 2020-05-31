# Frida MMO Maze Agent

This [Frida](https://frida.re/) agent is a solver for the [MMO Maze CTF](http://maze.liveoverflow.com/). This agent was designed to use the [Windows Maze v2.1 binary](https://static.allesctf.net/challenges/95a402a5b93a4424bcba9a46a0c9ef153025da6fe4aa57c6d35769d0c2a70878/Maze_v2.1_windows.zip).

The MMO Maze was an online multiplayer game with multiple CTF challenges embedded in it. By hacking the game client it was possible to reach otherwise unreachable areas in the game to solve CTF challenges.

The game is a Unity game compiled using il2Cpp. I extracted symbols from the game using [Il2CppDumper](https://github.com/Perfare/Il2CppDumper). Il2CppDumper's JSON file is used by this agent to allow easily hooking functions by name.

The CTF challenge solutions are described with comments in the [`agent/index.ts`](agent/index.ts) file. I solved all but the final "M4z3 Runn3r" challenge during the CTF.

This repo uses [frida-agent-example](https://github.com/oleavr/frida-agent-example) as a project structure template.

See https://lightbug14.gitbook.io/ for some documentation on the character controller used in the game.

### How to compile & load

Perform the following in the same directory as Maze.exe:

```sh
git clone https://github.com/bburky/mmo-maze-frida
cd mmo-maze-frida
npm install
../Maze.exe -logfile log.txt ; frida --runtime=v8 --debug Maze.exe --load _agent.js
```

Or start the process directly with:

```
frida  --runtime=v8 --debug --file ../Maze.exe --load _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.

### Debug

Attach to the Frida v8 runtime debugger using <chrome://inspect> or [attach to the debugger using VS Code](https://code.visualstudio.com/docs/nodejs/nodejs-debugging). A [launch.json](.vscode/launch.json) configuration is included in this repo to attach to a running debugger using VS Code.

### Extract symbols

Symbols were extracted from the game using [Il2CppDumper](https://github.com/Perfare/Il2CppDumper). The output `script.json` and `il2cpp.h` files are in the [il2cpp](il2cpp) directory.

These symbols are imported by [`maze.ts`](agent/maze.ts) and exposed with helper functions `nativePointer(symbol)` and `nativeFunction(symbol)` to lookup symbols and create Frida objects. There's some rudimentary automatic parsing of arguments for use with Frida's `NativeFunction`.

I couldn't find a way to easily import a C header file with JavaScript, so I used Ghidra to manually calculate offsets into structs. A definition of `size_t` was added to [`il2cpp.h`](il2cpp/il2cpp.h) to allow Ghidra to import it. The offsets are also available as comments in [`dump.cs`](il2cpp/dump.cs).
