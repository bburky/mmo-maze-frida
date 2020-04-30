# Frida MMO Maze Agent

### How to compile & load

```sh
$ git clone https://github.com/bburky/mmo-maze-frida
$ cd mmo-maze-frida/
$ npm install
$ Maze.exe
$ frida --runtime=v8 --debug Maze.exe --load _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.
