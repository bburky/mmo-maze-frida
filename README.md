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
