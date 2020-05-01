import { log, error } from "./logger";

export interface Il2cpp {
    ScriptMethod: Symbol[];
    // TODO: ScriptString
    ScriptMetadata: Symbol[];
    // TODO: ScriptMetadataMethod
    Addresses: number[];
}

export interface Symbol {
    Address: number;
    Name: string;
    Signature: string;
}

function parseType(type: string) {
    if (type.endsWith("*")) {
        return "pointer"
    } else if (type.endsWith("_t")) {
        return type.slice(0, -2);
    }
    // TODO: lookup structs and return an array
    return type;
}

function parseParameters(parameters: string) {
    // Matched parameter types will be something like:
    // TMPro_TextMeshProUGUI_o*, UnityEngine_Color_o, float, bool, bool
    const parsed = parameters.match(/(?<=\(|, )\w+\*?/g)!.map(parseType);
    log(parsed);
    return parsed;
}

export function nativeFunction(symbolName: string) {
    const symbol = symbols.get(symbolName);
    if (!symbol) {
        error(`Symbol not found ${symbolName}`);
        return null;
    }
    log(parseType(symbol.Signature.split(" ")[0]));
    return new NativeFunction(
        GameAssembly.base.add(symbol.Address),
        parseType(symbol.Signature.split(" ")[0]),
        parseParameters(symbol.Signature))
}

export function nativePointer(symbolName: string) {
    const symbol = symbols.get(symbolName);
    if (!symbol) {
        error(`Symbol not found ${symbolName}`);
        return null;
    }
    return GameAssembly.base.add(symbol.Address)   
}

// Import symbols extracted using https://github.com/Perfare/Il2CppDumper
import * as il2cpp from '../script.json';

export const symbols = new Map((<Il2cpp>il2cpp).ScriptMethod.map(m => [m.Name, m]));

export const GameAssembly = Module.load("GameAssembly.dll")

