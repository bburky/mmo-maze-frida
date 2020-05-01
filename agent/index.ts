import { log } from "./logger";

import * as maze from "./maze";
const symbols = maze.symbols
const GameAssembly = maze.GameAssembly;

log("")
log("[+] Hooking functions...");

let NormalMovement: NativePointer | null = null

log(`    Hooking NormalMovement$$ProcessPlanarMovement`);
const processPlanarMovement = Interceptor.attach(maze.nativePointer("Lightbug.CharacterControllerPro.Implementation.NormalMovement$$ProcessPlanarMovement")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called NormalMovement$$ProcessPlanarMovement`);
        NormalMovement = args[0]
        log(`    Saved NormalMovement pointer`);
        processPlanarMovement.detach()
        speedHack(5);
    }
});

///////////////////////////////////////////////////////////////////////////////
// Emoji
//
// Hook ServerManager$$sendEmoji and change its argument. Initially it is 0x17
// or 0x16, instead make a global counter and try a new emoji number each time
// the emoji action is triggered. Repeatedly trigger the emoji action (press 1)
// and the flag will appear.
//
// CSCG{Your_hack_got_reported_to_authorities!}

let emoji = 0x00; // Current emoji value
let ServerManager: NativePointer | null = null;

log(`    Hooking ServerManager$$sendEmoji`);
Interceptor.attach(maze.nativePointer("ServerManager$$sendEmoji")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called ServerManager$$sendEmoji`);
        ServerManager = args[0] // Save for future use
        log(`    Saved ServerManager pointer`);
        // Only change the emoji for the 1 key.
        if (args[1].toInt32() == 0x17) {
            log(`[+] Changing emoji from ${args[1]} to ${emoji}`);
            args[1] = new NativePointer(emoji++);
        }
    }
});

///////////////////////////////////////////////////////////////////////////////
// The Floor Is Lava
// 
// Change the jump apex and jump duration to 10 to allow jumping much higher
// and very slowly gliding back down. Explore the world until you find the
// lava area. Jump to reach the middle.
// 
// Manually trigger jumpHack() using the JavaScript debug console.
// 
// CSCG{FLYHAX_TOO_CLOSE_TO_THE_SUN!}

function jumpHack() {
    log(`[+] Breaking jumping so it is flying/gliding`);
    const verticalMovementParameters = NormalMovement!.add(56).readPointer();
    const jumpApexHeight = verticalMovementParameters.add(20);
    const jumpApexDuration = verticalMovementParameters.add(24);
    jumpApexHeight.writeFloat(10);
    jumpApexDuration.writeFloat(10);
}

// Setting speed to 10 works, but then you can't run because you are moved back
// to your previous location (by the server?). Set the speed to 5 to allow both
// walking and running.
function speedHack(newSpeed: number) {
    log(`[+] Setting planar movement speed to ${newSpeed}`);
    const planarMovementParameters = NormalMovement!.add(48).readPointer();
    const speed = planarMovementParameters.add(16);
    speed.writeFloat(newSpeed);
}

log("[+] Hooking done");

// Export some globals for use in debug console:
declare var global: any;
global.nativeFunction = maze.nativeFunction;
global.nativePointer = maze.nativePointer;
global.GameAssembly = GameAssembly;
global.symbols = symbols;
global.module = module;
global.getServerManager = () => ServerManager;
global.getNormalMovement = () => NormalMovement;
global.speedHack = speedHack;
global.jumpHack = jumpHack;
