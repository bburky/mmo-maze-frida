import { log } from "./logger";
import * as maze from "./maze";

log("")
log("[+] Hooking functions...");

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

log(`    Hooking ServerManager$$sendEmoji`);
Interceptor.attach(maze.nativePointer("ServerManager$$sendEmoji")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called ServerManager$$sendEmoji`);
        // Only change the emoji for the 1 key.
        const currentEmoji = args[1].toInt32();
        if (currentEmoji == 0x17) {
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
// CSCG{FLYHAX_TOO_CLOSE_TO_THE_SUN!}

function jumpHack(height: number, duration: number) {
    log(`[+] Breaking jumping so it is flying/gliding`);
    const verticalMovementParameters = NormalMovement!.add(56).readPointer();
    const jumpApexHeight = verticalMovementParameters.add(20);
    const jumpApexDuration = verticalMovementParameters.add(24);
    jumpApexHeight.writeFloat(height);
    jumpApexDuration.writeFloat(duration);
}

///////////////////////////////////////////////////////////////////////////////
// Maze Runner
//
// Change the planar movement speed to speed up walking and  running on the
// ground, and any horizontal movement in the air.
//
// Setting speed to 10 works, but then you can't run because you are moved back
// to your previous location (by the server?). Set the speed to 5 to allow both
// walking and running.
//
// If you're also flying with the jump hack, 10 is a good setting because you
// you can't run while in the air.
//
// Solve the maze runner challenge by enabling this with speed 10 and just
// walking to each checkpoint.
//
// CSCG{SPEEDH4X_MAZE_RUNNER_BUNNYYYY}

let NormalMovement: NativePointer | null = null

log(`    Hooking NormalMovement$$ProcessPlanarMovement`);
const processPlanarMovement = Interceptor.attach(maze.nativePointer("Lightbug.CharacterControllerPro.Implementation.NormalMovement$$ProcessPlanarMovement")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called NormalMovement$$ProcessPlanarMovement`);
        NormalMovement = args[0]
        log(`    Saved NormalMovement pointer`);
        processPlanarMovement.detach()
        jumpHack(20, 20);
        speedHack(10);
        // speedHack(5);
    }
});

function speedHack(newSpeed: number) {
    log(`[+] Setting planar movement speed to ${newSpeed}`);
    const planarMovementParameters = NormalMovement!.add(48).readPointer();
    const speed = planarMovementParameters.add(16);
    speed.writeFloat(newSpeed);
}

///////////////////////////////////////////////////////////////////////////////
// Map Radar
//
// Hook the NPCController$$newPosition function which gets passed each updated
// position and rotation for NPC players.
//
// To use run recordNpcPositions() in the debug console. Then wait a few
// minutes and dump the data with something like:
//    JSON.stringify(npcPositions.get(375))
//
// CSCG{RADAR_HACK_XYZ}

const npcPositions = new Map<number, number[][]>();

function recordNpcPositions() {
    log(`    Hooking NPCController$$newPosition`);
    // Hook using Interceptor.replace() because it allows specifying types of
    // arguments to give us arrays of floats, etc.
    const NPCController$$newPosition_args = ["pointer", ["float", "float", "float"], ["float", "float", "float"]];
    const NPCController$$newPosition = new NativeFunction(maze.nativePointer("NPCController$$newPosition")!, "void", NPCController$$newPosition_args);
    Interceptor.replace(
        NPCController$$newPosition,
        new NativeCallback((that: NativePointer, position: number[], rotation: number[]) => {
            // log("")
            // log(`[+] Called NPCController$$newPosition`);
            // log(`    NPC: ${position}`);

            // Unique(?) UID per NPC. I failed to read the NPC name.
            const NPCController = that.readPointer();
            const uid = NPCController.add(0x5C).readU32();

            let positions = npcPositions.get(uid);
            if (!positions) {
                positions = [];
                npcPositions.set(uid, positions)
            }
            // Push x and z coordinates
            positions.push([position[0], position[2]]);

            // Call the original function:
            return NPCController$$newPosition(that, position, rotation);
        }, 'void', NPCController$$newPosition_args)
    );
}

let ServerManager: NativePointer | null = null;

log(`    Hooking ServerManager$$Update`);
const ServerManager$$Update = Interceptor.attach(maze.nativePointer("ServerManager$$Update")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called ServerManager$$Update`);
        ServerManager = args[0] // Save for future use
        log(`    Saved ServerManager pointer`);
        ServerManager$$Update.detach()
    }
});

let CharacterActor: NativePointer | null = null;

log(`    Hooking CharacterActor$$UpdateCharacter`);
const updateCharacter = Interceptor.attach(maze.nativePointer("Lightbug.CharacterControllerPro.Core.CharacterActor$$UpdateCharacter")!, {
    onEnter: function (args) {
        log("")
        log(`[+] Called CharacterActor$$UpdateCharacter`);
        CharacterActor = args[0]
        log(`    Saved CharacterActor pointer`);
        updateCharacter.detach()
    }
});

log("[+] Hooking done");

// Export some globals for use in debug console:
declare const global: any;
global.maze = maze;
global.getServerManager = () => ServerManager;
global.getNormalMovement = () => NormalMovement;
global.getCharacterActor = () => CharacterActor;
global.speedHack = speedHack;
global.jumpHack = jumpHack;
global.recordNpcPositions = recordNpcPositions;
global.npcPositions = npcPositions;
