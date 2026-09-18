#!/usr/bin/env bash
set -euo pipefail

# ReSukiSU manual-hook integrator for Linux 4.19 non-GKI kernels.
# Designed to be run from the kernel source root AFTER:
#   curl -LSs "https://raw.githubusercontent.com/ReSukiSU/ReSukiSU/main/kernel/setup.sh" | bash
#
# The script is intentionally source-pattern based and idempotent. It refuses to
# silently "patch" a source tree when a required 4.19 hook target cannot be found.

ROOT="$(pwd)"
DEFCONFIG="${DEFCONFIG:-arch/arm64/configs/vendor/gauguin_user_defconfig}"

die() { echo "[ERROR] $*" >&2; exit 1; }
info() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }

[[ -d "$ROOT/drivers/kernelsu" ]] || die "drivers/kernelsu is missing. Run ReSukiSU kernel/setup.sh first."
[[ -f "$ROOT/Makefile" ]] || die "Run this script from the kernel source root."
[[ -f "$ROOT/$DEFCONFIG" ]] || die "Defconfig not found: $ROOT/$DEFCONFIG"

KVER="$(awk '
  /^VERSION[[:space:]]*=/ {v=$3}
  /^PATCHLEVEL[[:space:]]*=/ {p=$3}
  /^SUBLEVEL[[:space:]]*=/ {s=$3}
  END {print v "." p "." s}
' "$ROOT/Makefile")"
[[ "$KVER" == 4.19.* ]] || die "Expected Linux 4.19.x, detected: $KVER"
info "Detected kernel: $KVER"

python3 - "$ROOT" "$DEFCONFIG" <<'PY'
from pathlib import Path
import re
import shutil
import sys

root = Path(sys.argv[1])
defconfig = root / sys.argv[2]

def set_kconfig(path: Path, key: str, value: str) -> None:
    text = path.read_text()
    # Remove both active and explicitly-unset forms, then append one canonical line.
    text = re.sub(rf'(?m)^(?:{re.escape(key)}=.*|#\s*{re.escape(key)}\s+is\s+not\s+set)\n?', '', text)
    if text and not text.endswith('\n'):
        text += '\n'
    text += f"{key}={value}\n"
    path.write_text(text)

print("[+] Updating defconfig")
for key, value in [
    ("CONFIG_KSU", "y"),
    ("CONFIG_KSU_MANUAL_HOOK", "y"),
    ("CONFIG_KSU_SUSFS", "n"),
    ("CONFIG_KALLSYMS", "y"),
    # Current ReSukiSU docs say KALLSYMS_ALL avoids the required SELinux static
    # symbol export edits, so prefer the config switch over source churn.
    ("CONFIG_KALLSYMS_ALL", "y"),
]:
    set_kconfig(defconfig, key, value)

# Keep the automatic 4.19-compatible helpers enabled. Manual read/input hooks
# are still inserted below so the tree does not depend on the automatic path.
for key in [
    "CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK",
    "CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK",
    "CONFIG_KSU_MANUAL_HOOK_AUTO_INPUT_HOOK",
]:
    set_kconfig(defconfig, key, "y")


def body_bounds(text: str, start: int):
    """Return (open_brace_index, closing_brace_index) for one C function."""
    open_brace = text.find("{", start)
    if open_brace < 0:
        raise RuntimeError(f"function body opening brace not found near offset {start}")
    depth = 0
    i = open_brace
    in_str = None
    esc = False
    in_line_comment = False
    in_block_comment = False
    while i < len(text):
        c = text[i]
        n = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
        elif in_block_comment:
            if c == "*" and n == "/":
                in_block_comment = False
                i += 1
        elif in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == in_str:
                in_str = None
        else:
            if c == "/" and n == "/":
                in_line_comment = True
                i += 1
            elif c == "/" and n == "*":
                in_block_comment = True
                i += 1
            elif c in ('"', "'"):
                in_str = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return open_brace, i
        i += 1
    raise RuntimeError("unbalanced braces while parsing function body")

def backup(path: Path):
    bak = path.with_suffix(path.suffix + ".resukisu.bak")
    if not bak.exists():
        shutil.copy2(path, bak)

def write_once(path: Path, needle: str, replacement: str, label: str) -> None:
    text = path.read_text()
    if replacement.strip() in text:
        print(f"[=] {label}: already applied")
        return
    if needle not in text:
        raise RuntimeError(f"{label}: anchor not found in {path}")
    backup(path)
    path.write_text(text.replace(needle, replacement, 1))
    print(f"[+] {label}: applied")

# ---------------------------------------------------------------------------
# fs/exec.c
# ReSukiSU current manual hook: do_execveat_common() with pre/post hooks.
# ---------------------------------------------------------------------------
p = root / "fs/exec.c"
text = p.read_text()

exec_decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
\t\t\t\tvoid *argv, void *envp, int *flags);
__attribute__((hot))
extern int ksu_handle_post_execveat(int *fd, struct filename **filename_ptr,
\t\t\t\tvoid *argv, void *envp, int *flags, int *retval);
#endif

"""

if "ksu_handle_post_execveat" not in text:
    anchor = "static int do_execveat_common("
    if anchor not in text:
        raise RuntimeError("execve hook: do_execveat_common() not found")
    backup(p)
    text = text.replace(anchor, exec_decl + anchor, 1)

# Replace only the direct 4.19-style return inside do_execveat_common.
if "ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);" not in text:
    start_fn = text.find("static int do_execveat_common(")
    if start_fn < 0:
        raise RuntimeError("execve hook: do_execveat_common() not found")
    open_brace, close_brace = body_bounds(text, start_fn)
    body = text[open_brace + 1:close_brace]
    old = "return __do_execve_file(fd, filename, argv, envp, flags, NULL);"
    if old not in body:
        raise RuntimeError("execve hook: expected __do_execve_file() return not found")
    new = """#ifdef CONFIG_KSU_MANUAL_HOOK
\tint retval;
\tksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);

\tretval = __do_execve_file(fd, filename, argv, envp, flags, NULL);

\tksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);

\treturn retval;
#else
\treturn __do_execve_file(fd, filename, argv, envp, flags, NULL);
#endif"""
    body = body.replace(old, new, 1)
    backup(p)
    text = text[:open_brace + 1] + body + text[close_brace:]
    p.write_text(text)
    print("[+] fs/exec.c: execveat hook applied")


# ---------------------------------------------------------------------------
# fs/open.c - faccessat
# ---------------------------------------------------------------------------
p = root / "fs/open.c"
text = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
\t\t\t\tint *mode, int *flags);
#endif

"""
if "ksu_handle_faccessat" not in text:
    anchor = "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)"
    if anchor not in text:
        raise RuntimeError("faccessat hook: SYSCALL_DEFINE3(faccessat) not found")
    backup(p)
    text = text.replace(anchor, decl + anchor, 1)
if "ksu_handle_faccessat(&dfd, &filename, &mode, NULL);" not in text:
    start_fn = text.find("SYSCALL_DEFINE3(faccessat,")
    if start_fn < 0:
        raise RuntimeError("faccessat hook: syscall not found")
    open_brace, close_brace = body_bounds(text, start_fn)
    body = text[open_brace + 1:close_brace]
    m = re.search(r"(?m)^(\s*)return\s+do_faccessat\(dfd, filename, mode\);", body)
    if not m:
        raise RuntimeError("faccessat hook: do_faccessat return anchor not found")
    indent = m.group(1)
    call = (
        f"\n{indent}#ifdef CONFIG_KSU_MANUAL_HOOK\n"
        f"{indent}ksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
        f"{indent}#endif"
    )
    body = body[:m.start()] + call + "\n" + body[m.start():]
    backup(p)
    text = text[:open_brace + 1] + body + text[close_brace:]
p.write_text(text)
print("[+] fs/open.c: faccessat hook checked")

# ---------------------------------------------------------------------------
# kernel/reboot.c - required supercall hook for 3.11+
# ---------------------------------------------------------------------------
p = root / "kernel/reboot.c"
if p.exists():
    text = p.read_text()
    if "ksu_handle_sys_reboot" not in text:
        anchor = "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,"
        if anchor not in text:
            raise RuntimeError("reboot hook: kernel/reboot.c reboot syscall not found")
        decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif

"""
        backup(p)
        text = text.replace(anchor, decl + anchor, 1)
    if "ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);" not in text:
        # Insert immediately after the opening brace of the reboot syscall.
        pat = re.compile(
            r"(SYSCALL_DEFINE4\(reboot,\s*int,\s*magic1,\s*int,\s*magic2,\s*unsigned int,\s*cmd,\s*\n\s*void __user \*,\s*arg\)\n\{)",
            re.S,
        )
        m = pat.search(text)
        if not m:
            raise RuntimeError("reboot hook: could not parse reboot syscall signature")
        ins = """\n#ifdef CONFIG_KSU_MANUAL_HOOK
\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif"""
        backup(p)
        text = text[:m.end()] + ins + text[m.end():]
    p.write_text(text)
    print("[+] kernel/reboot.c: reboot hook checked")
else:
    raise RuntimeError("kernel/reboot.c is missing")

# ---------------------------------------------------------------------------
# fs/read_write.c - 4.19 sys_read hook using current ReSukiSU symbol name.
# ---------------------------------------------------------------------------
p = root / "fs/read_write.c"
text = p.read_text()
decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_init_rc_hook __read_mostly;
extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,
\t\t\t\tchar __user **buf_ptr, size_t *count_ptr);
#endif

"""
if "ksu_handle_sys_read" not in text:
    anchor = "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)"
    if anchor not in text:
        raise RuntimeError("sys_read hook: SYSCALL_DEFINE3(read) not found")
    backup(p)
    text = text.replace(anchor, decl + anchor, 1)

if "ksu_handle_sys_read(fd, &buf, &count);" not in text:
    pat = re.compile(
        r"(SYSCALL_DEFINE3\(read,\s*unsigned int,\s*fd,\s*char __user \*,\s*buf,\s*size_t,\s*count\)\n\{)(.*?)("
        r"\n\})",
        re.S,
    )
    m = pat.search(text)
    if not m:
        raise RuntimeError("sys_read hook: could not parse read syscall")
    body = m.group(2)
    if "ksu_handle_sys_read(fd, &buf, &count);" not in body:
        # For 4.19, the official ReSukiSU manual reference hooks the read path
        # used by ksys_read. Insert immediately before the final ksys_read return.
        mret = re.search(r"(?m)^(\s*)return\s+ksys_read\(fd,\s*buf,\s*count\);", body)
        if not mret:
            raise RuntimeError("sys_read hook: expected 4.19 ksys_read return not found")
        indent = mret.group(1)
        new = (
            f"#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"{indent}if (unlikely(ksu_init_rc_hook))\n"
            f"{indent}\tksu_handle_sys_read(fd, &buf, &count);\n"
            f"#endif\n"
            f"{indent}return ksys_read(fd, buf, count);"
        )
        body = body[:mret.start()] + new + body[mret.end():]
        backup(p)
        text = text[:m.start(2)] + body + text[m.end(2):]
p.write_text(text)
print("[+] fs/read_write.c: sys_read hook checked")

# ---------------------------------------------------------------------------
# fs/stat.c - required path hook + newfstat return hook + optional fstat64 return.
# ---------------------------------------------------------------------------
p = root / "fs/stat.c"
text = p.read_text()

if "ksu_handle_stat" not in text:
    anchor = "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,"
    if anchor not in text:
        raise RuntimeError("stat hook: newfstatat syscall not found")
    decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
__attribute__((hot))
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
\t\t\t\tint *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf_ptr);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
extern void ksu_handle_fstat64_ret(unsigned long *fd, struct stat64 __user **statbuf_ptr);
#endif
#endif

"""
    backup(p)
    text = text.replace(anchor, decl + anchor, 1)

if "ksu_handle_stat(&dfd, &filename, &flag);" not in text:
    # Hook both newfstatat and fstatat64, when present.
    funcs = ["newfstatat", "fstatat64"]
    for name in funcs:
        marker = f"SYSCALL_DEFINE4({name},"
        idx = text.find(marker)
        if idx < 0:
            if name == "fstatat64":
                continue
            raise RuntimeError(f"stat hook: {name} syscall not found")
        open_brace, close_brace = body_bounds(text, idx)
        body = text[open_brace + 1:close_brace]
        mcall = re.search(
            r"(?m)^(\s*)error\s*=\s*vfs_fstatat\(dfd,\s*filename,\s*&stat,\s*flag\);",
            body,
        )
        if not mcall:
            raise RuntimeError(f"stat hook: {name} vfs_fstatat() anchor not found")
        indent = mcall.group(1)
        call = (
            f"#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"{indent}ksu_handle_stat(&dfd, &filename, &flag);\n"
            f"#endif\n"
            f"{mcall.group(1)}error = vfs_fstatat(dfd, filename, &stat, flag);"
        )
        body = body[:mcall.start()] + call + body[mcall.end():]
        backup(p)
        text = text[:open_brace + 1] + body + text[close_brace:]
# newfstat return hook
if "ksu_handle_newfstat_ret(&fd, &statbuf);" not in text:
    marker = "SYSCALL_DEFINE2(newfstat, unsigned int, fd, struct stat __user *, statbuf)"
    idx = text.find(marker)
    if idx >= 0:
        _, end = body_bounds(text, idx)
        body = text[idx:end]
        mret = re.search(
            r"(?m)(^\s*if\s*\(!error\)\s*\n\s*error\s*=\s*cp_new_stat\(&stat,\s*statbuf\);)",
            body,
        )
        if not mret:
            raise RuntimeError("stat return hook: newfstat body differs from expected 4.19 form")
        indent = re.match(r"\s*", mret.group(1).splitlines()[0]).group(0)
        new = mret.group(1) + (
            f"\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
            f"{indent}ksu_handle_newfstat_ret(&fd, &statbuf);\n"
            f"#endif"
        )
        body = body[:mret.start()] + new + body[mret.end():]
        text = text[:idx] + body + text[end:]
    else:
        raise RuntimeError("stat return hook: newfstat syscall not found")

# optional 32-bit fstat64 return hook
if "ksu_handle_fstat64_ret(&fd, &statbuf);" not in text:
    marker = "SYSCALL_DEFINE2(fstat64,"
    idx = text.find(marker)
    if idx >= 0:
        _, end = body_bounds(text, idx)
        body = text[idx:end]
        mret = re.search(
            r"(?m)(^\s*if\s*\(!error\)\s*\n\s*error\s*=\s*cp_new_stat64\(&stat,\s*statbuf\);)",
            body,
        )
        if mret:
            indent = re.match(r"\s*", mret.group(1).splitlines()[0]).group(0)
            new = mret.group(1) + (
                f"\n#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                f"{indent}ksu_handle_fstat64_ret(&fd, &statbuf);\n"
                f"#endif"
            )
            body = body[:mret.start()] + new + body[mret.end():]
            text = text[:idx] + body + text[end:]
p.write_text(text)
print("[+] fs/stat.c: stat hooks checked")

# ---------------------------------------------------------------------------
# drivers/input/input.c - current manual input hook (optional in ReSukiSU,
# but retained here because it is already stable on this kernel family).
# ---------------------------------------------------------------------------
p = root / "drivers/input/input.c"
text = p.read_text()
if "ksu_handle_input_handle_event(&type, &code, &value);" not in text:
    anchor = "void input_event(struct input_dev *dev,"
    if anchor in text:
        decl = """#ifdef CONFIG_KSU_MANUAL_HOOK
extern bool ksu_input_hook __read_mostly;
extern __attribute__((cold)) int ksu_handle_input_handle_event(
			unsigned int *type, unsigned int *code, int *value);
#endif

"""
        if "ksu_handle_input_handle_event(" not in text:
            backup(p)
            text = text.replace(anchor, decl + anchor, 1)
        start_fn = text.find(anchor)
        open_brace, close_brace = body_bounds(text, start_fn)
        body = text[open_brace + 1:close_brace]
        mflags = re.search(r"(?m)^(\s*)unsigned long flags\s*;\s*$", body)
        if not mflags:
            warn("drivers/input/input.c: unsigned long flags declaration not found; relying on AUTO_INPUT_HOOK")
        else:
            indent = mflags.group(1)
            ins = (
                f"{mflags.group(0)}\n\n"
                f"#ifdef CONFIG_KSU_MANUAL_HOOK\n"
                f"{indent}if (unlikely(ksu_input_hook))\n"
                f"{indent}\tksu_handle_input_handle_event(&type, &code, &value);\n"
                f"#endif"
            )
            body = body[:mflags.start()] + ins + body[mflags.end():]
            backup(p)
            text = text[:open_brace + 1] + body + text[close_brace:]
            p.write_text(text)
            print("[+] drivers/input/input.c: input hook applied")
    else:
        warn("drivers/input/input.c: input_event() not found; relying on AUTO_INPUT_HOOK")
else:
    print("[=] drivers/input/input.c: input hook already present")
# The old SukiSU patch used a devpts/pty hook that is not part of the current
# ReSukiSU 4.19 manual-integration reference. Do not add it to a clean tree.

# ---------------------------------------------------------------------------
# Final verification
# ---------------------------------------------------------------------------
checks = [
    (root / "fs/exec.c", "ksu_handle_execveat(&fd, &filename, &argv, &envp, &flags);", "fs/exec.c exec hook"),
    (root / "fs/exec.c", "ksu_handle_post_execveat(&fd, &filename, &argv, &envp, &flags, &retval);", "fs/exec.c post-exec hook"),
    (root / "fs/open.c", "ksu_handle_faccessat(&dfd, &filename, &mode, NULL);", "fs/open.c faccessat hook"),
    (root / "kernel/reboot.c", "ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);", "kernel/reboot.c reboot hook"),
    (root / "fs/read_write.c", "ksu_handle_sys_read(fd, &buf, &count);", "fs/read_write.c read hook"),
    (root / "fs/stat.c", "ksu_handle_stat(&dfd, &filename, &flag);", "fs/stat.c stat hook"),
    (root / "fs/stat.c", "ksu_handle_newfstat_ret(&fd, &statbuf);", "fs/stat.c newfstat return hook"),
]
for path, needle, label in checks:
    t = path.read_text()
    if needle not in t:
        raise RuntimeError(f"verification failed: {label}")
    print(f"[OK] {label}")

stat_text = (root / "fs/stat.c").read_text()
if "SYSCALL_DEFINE2(fstat64," in stat_text and "ksu_handle_fstat64_ret(&fd, &statbuf);" not in stat_text:
    raise RuntimeError("verification failed: fstat64 return hook is missing")
if "ksu_handle_input_handle_event(&type, &code, &value);" in (root / "drivers/input/input.c").read_text():
    print("[OK] drivers/input/input.c input hook")

print("[OK] ReSukiSU 4.19 manual hooks/configuration are ready.")
PY
