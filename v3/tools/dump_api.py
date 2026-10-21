#!/usr/bin/env python3
import os
import re
import sys

SRC_EXT = ('.c', '.h')
SKIP_DIRS = {'tests', 'out', 'in', 'logs', 'keys', 'build', '.git'}

RE_INCLUDE = re.compile(r'^\s*#\s*include\s+[<"].*[>"]\s*$')
RE_DEFINE = re.compile(r'^\s*#\s*define\s+(\w+)(\([^)]*\))?\s*(.*)$')
RE_ENUM = re.compile(r'\benum\b[^{;]*\{')
RE_STRUCT = re.compile(r'\b(struct|union)\b[^{;]*\{')
RE_TYPEDEF = re.compile(r'^\s*typedef\b')
RE_FUNC = re.compile(
    r'^[A-Za-z_][\w\s\*\(\),]*?\b(\w+)\s*\(([^;{}]*)\)\s*(\{?;?)\s*$'
)


def strip_comments(text):
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i:i+2] == '/*':
            j = text.find('*/', i + 2)
            if j < 0:
                out.append(' ' * (n - i))
                break
            out.append(' ' * (j + 2 - i))
            i = j + 2
        elif text[i:i+2] == '//':
            j = text.find('\n', i)
            if j < 0:
                out.append(' ' * (n - i))
                break
            out.append(' ' * (j - i))
            i = j
        elif text[i] == '"' or text[i] == "'":
            q = text[i]
            out.append(text[i])
            i += 1
            while i < n:
                out.append(text[i])
                if text[i] == '\\' and i + 1 < n:
                    out.append(text[i+1])
                    i += 2
                    continue
                if text[i] == q:
                    i += 1
                    break
                i += 1
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)


def find_matching_brace(text, open_idx):
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def collapse_ws(s):
    return re.sub(r'\s+', ' ', s).strip()


def parse_file(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        raw = f.read()
    text = strip_comments(raw)
    lines = text.split('\n')

    defines = []
    for ln in lines:
        m = RE_DEFINE.match(ln)
        if m:
            name = m.group(1)
            args = m.group(2) or ''
            val = m.group(3) or ''
            defines.append((name, args, collapse_ws(val)))

    enums = []
    structs = []
    typedefs = []

    i = 0
    n = len(text)
    while i < n:
        m = RE_ENUM.search(text, i)
        ms = RE_STRUCT.search(text, i)
        mt = RE_TYPEDEF.match(text, i)
        best = None
        kind = None
        for cand, k in ((m, 'enum'), (ms, 'struct'), (mt, 'typedef')):
            if cand is not None:
                if best is None or cand.start() < best.start():
                    best = cand
                    kind = k
        if best is None:
            break
        start = best.start()
        ob = text.find('{', start)
        if ob < 0:
            i = best.end()
            continue
        cb = find_matching_brace(text, ob)
        if cb < 0:
            break
        body = text[ob+1:cb]
        head = text[start:ob]
        tail_start = cb + 1
        tail_end = text.find(';', tail_start)
        if tail_end < 0:
            tail_end = tail_start
        tail = text[tail_start:tail_end].strip()
        if kind == 'enum':
            enums.append((collapse_ws(head), collapse_ws(body), tail))
        elif kind == 'struct':
            structs.append((collapse_ws(head), collapse_ws(body), tail))
        elif kind == 'typedef':
            typedefs.append(collapse_ws(text[start:tail_end+1]))
        i = tail_end + 1

    funcs = []
    globals_ = []
    i = 0
    while i < n:
        if text[i] in ' \t\r\n':
            i += 1
            continue
        if text[i] == '#':
            j = text.find('\n', i)
            i = j + 1 if j >= 0 else n
            continue
        j = text.find('\n', i)
        if j < 0:
            j = n
        line = text[i:j].strip()
        if not line:
            i = j + 1
            continue
        if line.startswith('#'):
            i = j + 1
            continue
        if line.startswith('typedef') or line.startswith('enum') or line.startswith('struct') or line.startswith('union'):
            i = j + 1
            continue
        mf = RE_FUNC.match(line + ' ')
        if mf and '(' in line and not line.startswith('return') and not line.startswith('if') \
           and not line.startswith('while') and not line.startswith('for') and not line.startswith('switch'):
            name = mf.group(1)
            params = collapse_ws(mf.group(2))
            ret = collapse_ws(line[:line.rfind(name, 0, line.find('('))]).strip()
            if ret and not ret.endswith('='):
                funcs.append((ret, name, params))
            i = j + 1
            continue
        if line.endswith(';') and '(' not in line and not line.startswith('return') \
           and ' ' in line and not re.match(r'^(if|while|for|switch|case|goto|break|continue)\b', line):
            globals_.append(collapse_ws(line))
        i = j + 1

    return {
        'defines': defines,
        'enums': enums,
        'structs': structs,
        'typedefs': typedefs,
        'funcs': funcs,
        'globals': globals_,
    }


def iter_sources(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith('.')]
        for fn in sorted(filenames):
            if fn.endswith(SRC_EXT):
                yield os.path.join(dirpath, fn)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else '.'
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    files = sorted(iter_sources(root))

    parts = []
    parts.append('# API dump\n')
    parts.append(f'root: `{os.path.abspath(root)}`\n')
    parts.append(f'files: {len(files)}\n')

    for path in files:
        rel = os.path.relpath(path, root)
        try:
            info = parse_file(path)
        except Exception as e:
            parts.append(f'\n## `{rel}`\n\nERROR: {e}\n')
            continue
        parts.append(f'\n## `{rel}`\n')

        if info['defines']:
            parts.append('\n### #define\n\n')
            for name, args, val in info['defines']:
                parts.append(f'- `#define {name}{args} {val}`\n')

        if info['enums']:
            parts.append('\n### enum\n\n')
            for head, body, tail in info['enums']:
                parts.append(f'- `{head} {{ {body} }} {tail}`\n')

        if info['structs']:
            parts.append('\n### struct/union\n\n')
            for head, body, tail in info['structs']:
                parts.append(f'- `{head} {{ {body} }} {tail}`\n')

        if info['typedefs']:
            parts.append('\n### typedef\n\n')
            for t in info['typedefs']:
                parts.append(f'- `{t}`\n')

        if info['globals']:
            parts.append('\n### globals\n\n')
            for g in info['globals']:
                parts.append(f'- `{g}`\n')

        if info['funcs']:
            parts.append('\n### functions\n\n')
            for ret, name, params in info['funcs']:
                parts.append(f'- `{ret} {name}({params})`\n')

    text = ''.join(parts)
    if out_path:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'wrote {out_path} ({len(files)} files)')
    else:
        sys.stdout.write(text)


if __name__ == '__main__':
    main()
