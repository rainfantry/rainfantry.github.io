# Chapter 0A — Setting Up the Armoury

Before any operation, you check your kit. Before you check your kit, you
need a fucking armoury. This chapter is the armoury build-out — getting
your development environment squared away so you can compile, link, and
execute C programs against the Win32 API.

Skip nothing. A jammed weapon in the field starts here — in the armoury,
with the wrong tools or missing parts. Get this right once. Then forget
about it and focus on the fight.

---

## 1. Installing Visual Studio Build Tools (Weapons Requisition)

You need `cl.exe` — Microsoft's C/C++ compiler. This is the weapon forge.
Without it, you're holding blueprints with no metal.

You do NOT need full Visual Studio. That's an APC when all you need is a
rifle. We're getting **Visual Studio Build Tools** — the compiler, linker,
and SDK headers. Nothing else.

### The Requisition Order

1. Go to [https://visualstudio.microsoft.com/downloads/](https://visualstudio.microsoft.com/downloads/)
2. Scroll past the big Visual Studio buttons. Under **"All Downloads"**, find
   **"Tools for Visual Studio"** → **"Build Tools for Visual Studio 2022"**
3. Download and run the installer
4. When the workload selector appears, tick **"Desktop development with C++"**
5. Hit Install

That workload gives you:

| Tool | What It Is |
|------|-----------|
| `cl.exe` | The C/C++ compiler — forges source into object files |
| `link.exe` | The linker — welds object files into executables |
| Windows SDK headers | `windows.h`, `winternl.h`, etc. — the API surface maps |
| C runtime libraries | Standard `stdio.h`, `stdlib.h`, etc. |

**Size:** ~2-3 GB. Let it install. Go do pushups.

> **NOTE:** If you already have Visual Studio 2022 Community installed with the
> C++ workload, you're already kitted out. Don't double-install. Check by
> searching for "x64 Native Tools Command Prompt" in Start Menu — if it
> exists, you're good.

---

## 2. Developer Command Prompt (The Armoury Door)

Here's where most operators get jammed on day one.

`cl.exe` doesn't live on your normal PATH. If you open PowerShell or Git Bash
and type `cl`, you'll get:

```
'cl' is not recognized as an internal or external command
```

That's not a malfunction. The weapon exists — you just haven't opened the
armoury door. The armoury door is the **Developer Command Prompt**.

### Opening the Door

1. Hit Start (or Win key)
2. Search: **"x64 Native Tools Command Prompt for VS 2022"**
3. Open it
4. **Pin it to your taskbar.** You will use this every single time you compile.

That's it. When this prompt opens, it automatically runs a script that sets
three critical environment variables:

| Variable | What It Points To |
|----------|------------------|
| `PATH` | Adds `cl.exe`, `link.exe`, and SDK tools to your executable search path |
| `INCLUDE` | Tells the compiler where to find `windows.h` and all SDK headers |
| `LIB` | Tells the linker where to find `kernel32.lib` and other import libraries |

Without these three variables, the compiler can't find its own tools, the
headers, or the libraries. The Developer Command Prompt sets all three in
one shot. That's why you use it.

### Alternative: Source It from Any Terminal

If you want `cl.exe` available in a regular `cmd.exe` or a VS Code terminal,
run the setup script manually:

```cmd
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
```

Or, if you installed full Visual Studio Community:

```cmd
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

One of those paths will exist depending on what you installed. Run it once
at the start of your session. The variables persist for the life of that
terminal window.

> **TIP:** If you can't find your install, search your `C:\Program Files`
> for `vcvars64.bat`. The path varies by edition (BuildTools vs Community vs
> Professional) but the script is always the same.

---

## 3. Your First Compile (Dry Fire Drill)

Armoury's open. Let's confirm the weapon system is functional.

Create a file called `hello.c`:

```c
#include <stdio.h>

int main() {
    printf("[+] Weapons system operational.\n");
    return 0;
}
```

In the Developer Command Prompt, navigate to wherever you saved it and compile:

```cmd
cl.exe hello.c /Fe:hello.exe
```

Then run:

```cmd
hello.exe
```

Expected output:

```
[+] Weapons system operational.
```

If you see that — your armoury is functional. Compiler works. Linker works.
Headers resolve. The forge is hot.

Delete `hello.c` and `hello.exe` when you're done. This was a functions check,
not kit you keep.

---

## 4. Compile Flags (Weapon Modifications)

Every weapon comes stock. Then you modify it for the mission. `cl.exe` takes
flags that change how the binary is built. Here are the ones we use:

| Flag | Designation | What It Does |
|------|------------|--------------|
| `/Fe:output.exe` | Designate the weapon | Names the output binary. Without it, you get `filename.exe` by default. |
| `/O1` | Strip the serial numbers | Optimise for size. Smaller binary = fewer bytes for signature scanners to pattern-match against. Less material, less detectable. |
| `/GS-` | Disable the safety catch | Turns off stack buffer security checks (`__security_cookie` / stack canary). Reduces noise — fewer detectable compiler-inserted patterns. We manage our own memory. |
| `/W4` | Paranoid mode | Warning level 4. The compiler screams at you about everything — unused variables, implicit conversions, suspicious casts. Use this during development. Better to get yelled at in the armoury than to misfire in the field. |

### The Standard Compile for This Project

```cmd
cl.exe filename.c /Fe:output.exe /O1 /GS-
```

That's it. One line. One weapon. Every source file in this repo compiles
the same way.

For development and testing, add `/W4` to catch issues early:

```cmd
cl.exe filename.c /Fe:output.exe /O1 /GS- /W4
```

Drop `/W4` for the final build — some Win32 headers throw warnings at level
4 that aren't our problem.

---

## 5. Project Directory Structure (Base Layout)

Know your AO. Here's the base layout:

```
vader-toctou/
│
├── BOOK/                           Field Manual — doctrine chapters
│   ├── 00_OVERVIEW.md              Mission Brief
│   ├── 00A_DEV_ENVIRONMENT.md      ← YOU ARE HERE (Armoury Setup)
│   ├── 01_HANDLES_AND_OBJECTS.md   Grips & Arsenal
│   ├── ...                         Chapters 02-10
│   └── GLOSSARY.md                 Field Reference Card
│
├── TESTS/                          Dry fire drills — safe API experiments
│   ├── test01_handles.c            One test per concept
│   ├── test02_paths.c
│   └── ...
│
├── BUILDING_BLOCKS/                Annotated weapon systems (answer key)
│   ├── bb1_junction_annotated.c
│   ├── bb2_oplock_annotated.c
│   └── bb3_trigger_annotated.c
│
├── LIVE/                           Live fire — operator writes these
│   ├── bb1_junction.c
│   └── ...
│
└── .gitignore                      Blocks *.exe, *.obj, *.pdb — no
                                    compiled binaries enter the repo
```

### Where You Compile From

Open your Developer Command Prompt. Navigate to the directory containing
the source file you want to compile:

- **Dry fire:** `cd C:\Users\gwu07\Desktop\vader-toctou\TESTS`
- **Live fire:** `cd C:\Users\gwu07\Desktop\vader-toctou\LIVE`
- **Building blocks:** `cd C:\Users\gwu07\Desktop\vader-toctou\BUILDING_BLOCKS`

Compile in-place. The `.exe` lands in the same directory. That's fine —
`.gitignore` blocks all compiled output:

```
*.exe
*.obj
*.pdb
*.ilk
```

**Binaries never enter the repo.** Source in, source out. Compile on the
machine where you'll run it. The source code is the weapon blueprint.
The compiled binary is the assembled weapon. Blueprints travel. Assembled
weapons stay on the operating base.

---

## 6. Testing Your Setup (Shakedown Patrol)

Final check. Compile and run the first test program as a full end-to-end
validation of your development environment.

```cmd
cd C:\Users\gwu07\Desktop\vader-toctou\TESTS
cl.exe test01_handles.c /Fe:test01_handles.exe /O1 /W4
test01_handles.exe
```

You should see output from five drills — handle creation, cross-handle
reads, failure handling, exclusive access, handle value inspection. If all
five drills complete and the output ends with:

```
[+]  All handles closed. Range swept.
[+]  Weapons returned. Brass policed.
[+]  DRILL COMPLETE.
```

Your armoury is operational. Full weapons system functional. You're clear
to proceed to Chapter 1.

### Common Malfunctions and Field Repairs

**`'cl' is not recognized as an internal or external command`**

You're not in the Developer Command Prompt. Either:
- Open "x64 Native Tools Command Prompt for VS 2022" from the Start Menu, or
- Run `vcvars64.bat` in your current terminal (see Section 2 above)

The compiler exists. You just haven't opened the armoury door.

---

**`fatal error C1083: Cannot open include file: 'windows.h': No such file or directory`**

The Windows SDK is not installed. The compiler can forge, but it has no
API surface maps. Fix:

1. Open **Visual Studio Installer** (search in Start Menu)
2. Click **Modify** on your Build Tools installation
3. Ensure **"Desktop development with C++"** workload is ticked
4. On the right panel, ensure **"Windows 10/11 SDK"** is checked
5. Hit Modify. Wait. Try again.

---

**`error LNK2019: unresolved external symbol _main`**

Your source file doesn't have a `main()` function, or you're compiling a
header file by accident. Check you're pointing `cl.exe` at a `.c` file
that contains `int main()`.

---

**`error LNK2019: unresolved external symbol __imp_SomeFunction`**

Missing a library at link time. For basic Win32 programs (everything in
this repo), the default libraries should cover it. If you hit this on
advanced programs, add the library explicitly:

```cmd
cl.exe filename.c /Fe:output.exe /link kernel32.lib
```

You shouldn't need this for any program in this syllabus. If you do,
something else is wrong — re-check your source.

---

## 7. VS Code Integration (Optional — Field Laptop Setup)

You have VS Code. It works fine for editing source files. But you do NOT
need it to compile or run anything. The Developer Command Prompt is the
weapon forge. VS Code is just the workbench where you lay out the parts.

If you want to keep things in one window:

1. Install the **C/C++ extension** by Microsoft (extension ID: `ms-vscode.cpptools`).
   This gives you syntax highlighting, IntelliSense, and error squiggles.

2. Open a terminal inside VS Code (`Ctrl+`` ` or Terminal → New Terminal).

3. Run `vcvars64.bat` in that terminal to load the compiler environment:
   ```cmd
   "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
   ```

4. Now `cl.exe` works from inside VS Code's integrated terminal.

That said — don't overcomplicate it. Two windows work fine:
- **VS Code** for reading and writing code
- **Developer Command Prompt** for compiling and running

Keep it simple. The fewer moving parts in your setup, the fewer things
that can jam. A rifle that works beats a weapon system you can't field-strip.

---

## Kit Check Complete

Your armoury is built. You have:

- [x] `cl.exe` — the forge (compiler)
- [x] `link.exe` — the welder (linker)
- [x] Windows SDK — the API surface maps (headers)
- [x] Developer Command Prompt — the armoury door
- [x] A verified compile-and-run cycle
- [x] Knowledge of the base layout

No excuses. No "my tools don't work." You just proved they do.

Proceed to **Chapter 1 — Handles: Your Grip on the Weapon**.
