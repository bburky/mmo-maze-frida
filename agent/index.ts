import { log } from "./logger";

interface Symbol {
    Address: number;
    Name: string;
    Signature: string;
}

// Import symbols extracted using https://github.com/Perfare/Il2CppDumper
import * as il2cpp from '../script.json';
const symbols = new Map<string, Symbol>(il2cpp.ScriptMethod.map(m => [ m.Name, m ]));

const module = Module.load("GameAssembly.dll")
const baseAddr = Module.getBaseAddress("GameAssembly.dll");
const ServerManager$$sendEmoji = symbols.get("ServerManager$$sendEmoji")!;

console.log("Hooking...");

///////////////////////////////////////////////////////////////////////////////
// Emoji
//
// Hook ServerManager$$sendEmoji and change its argument. Initially it is 0x17
// or 0x16, instead make a global counter and try a new emoji number each time
// the emoji action is triggered. Repeatedly trigger the emoji action (press 1)
// and the flag will appear.
//
// CSCG{Your_hack_got_reported_to_authorities!}

// Current emoji value:
let emoji = 0x00;

Interceptor.attach(baseAddr.add(ServerManager$$sendEmoji.Address), {
    onEnter: function (args) {
        console.log("")
        console.log(`[+] Called ${ServerManager$$sendEmoji.Signature}`);
        console.log(`Changing emoji from ${args[1]} to ${emoji}`);
        args[1] = new NativePointer(emoji++);
    }
});

console.log("Init done");

// Export some globals for use in debug console:
declare var global: any;
global.baseAddr = baseAddr;
global.il2cpp = il2cpp;
global.symbols = symbols;
