//! The slice of the Lua 5.1 C API that `script.zig` uses, declared by hand.
//!
//! Not translated from `lua.h`. The 5.1 API has been frozen since 2006 and
//! LuaJIT implements it unchanged, so a dozen `extern` declarations are a
//! smaller and steadier thing to own than a translate-c step — which, on
//! NixOS, cannot find a native libc's headers at all. See build/luajit.zig.
//!
//! Macros in `lua.h` (`lua_pop`, `lua_getglobal`, `lua_tostring`, …) are
//! functions here, with the same expansions.

pub const State = opaque {};
pub const CFunction = *const fn (?*State) callconv(.c) c_int;
pub const Integer = isize;
pub const Number = f64;

pub const multret: c_int = -1;
pub const registry_index: c_int = -10000;
pub const globals_index: c_int = -10002;

pub const Type = enum(c_int) {
    none = -1,
    nil = 0,
    boolean = 1,
    light_userdata = 2,
    number = 3,
    string = 4,
    table = 5,
    function = 6,
    userdata = 7,
    thread = 8,
    _,
};

/// `lua_pcall` and the loaders' results.
pub const Status = enum(c_int) {
    ok = 0,
    yield = 1,
    runtime = 2,
    syntax = 3,
    memory = 4,
    handler = 5,
    file = 6,
    _,
};

pub extern fn luaL_newstate() ?*State;
pub extern fn lua_close(L: *State) void;
pub extern fn luaL_openlibs(L: *State) void;
pub extern fn luaL_loadbuffer(L: *State, buffer: [*]const u8, size: usize, name: [*:0]const u8) Status;
pub extern fn lua_pcall(L: *State, nargs: c_int, nresults: c_int, errfunc: c_int) Status;

pub extern fn lua_gettop(L: *State) c_int;
pub extern fn lua_settop(L: *State, index: c_int) void;
pub extern fn lua_pushvalue(L: *State, index: c_int) void;
pub extern fn lua_type(L: *State, index: c_int) Type;

pub extern fn lua_pushnil(L: *State) void;
pub extern fn lua_pushinteger(L: *State, n: Integer) void;
pub extern fn lua_pushlstring(L: *State, s: [*]const u8, len: usize) void;
pub extern fn lua_pushcclosure(L: *State, f: CFunction, n: c_int) void;
pub extern fn lua_tolstring(L: *State, index: c_int, len: *usize) ?[*]const u8;

pub extern fn lua_createtable(L: *State, narr: c_int, nrec: c_int) void;
pub extern fn lua_getfield(L: *State, index: c_int, key: [*:0]const u8) void;
pub extern fn lua_setfield(L: *State, index: c_int, key: [*:0]const u8) void;
pub extern fn lua_settable(L: *State, index: c_int) void;
pub extern fn lua_rawseti(L: *State, index: c_int, n: c_int) void;

pub fn pop(L: *State, n: c_int) void {
    lua_settop(L, -n - 1);
}

pub fn getGlobal(L: *State, name: [*:0]const u8) void {
    lua_getfield(L, globals_index, name);
}

pub fn setGlobal(L: *State, name: [*:0]const u8) void {
    lua_setfield(L, globals_index, name);
}

pub fn pushString(L: *State, s: []const u8) void {
    lua_pushlstring(L, s.ptr, s.len);
}

/// The string at `index`, or null when it is neither a string nor a number.
/// Borrowed from the Lua value: valid while that value stays on the stack.
pub fn toString(L: *State, index: c_int) ?[]const u8 {
    var len: usize = 0;
    const ptr = lua_tolstring(L, index, &len) orelse return null;
    return ptr[0..len];
}
