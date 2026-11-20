"""Builds each page as one file, with its CSS, JS and WASM inside.

Browsers won't load module scripts or WASM from a page opened straight from disk, so a
saved copy of a normal page doesn't work. A single file does: pkg/recover.html still works
with the server gone, and pkg/unravelrule.html is the client to download, check and run
locally.
"""

import base64
import re
from pathlib import Path

web = Path(__file__).parent
css = (web / "static/style.css").read_text()
glue = (web / "pkg/unravel_web.js").read_text()
wasm = base64.b64encode((web / "pkg/unravel_web_bg.wasm").read_bytes()).decode()


def replace_once(text, old, new):
    assert text.count(old) == 1, f"expected exactly one {old!r}"
    return text.replace(old, new)


# Turn the wasm-bindgen glue module into plain declarations the inline script can use.
exports = re.findall(r"^export function (\w+)", glue, re.M)
glue = re.sub(r"^export function ", "function ", glue, flags=re.M)
glue = replace_once(glue, "export { initSync, __wbg_init as default };", "")
inline = (
    glue
    + f"\nconst u = {{ {', '.join(exports)} }};\n"
    + f'const WASM = Uint8Array.from(atob("{wasm}"), (c) => c.charCodeAt(0));\n'
)


def bundle(html, js, out):
    page = (web / "static" / html).read_text()
    script = (web / "static" / js).read_text()
    script = replace_once(script, 'import init, * as u from "./pkg/unravel_web.js";\n', inline)
    script = replace_once(script, "await init();", "await __wbg_init({ module_or_path: WASM });")
    page = replace_once(page, '<link rel="stylesheet" href="style.css">', f"<style>\n{css}</style>")
    icon = base64.b64encode((web / "static/favicon-48.png").read_bytes()).decode()
    page = replace_once(page, 'href="favicon-48.png"', f'href="data:image/png;base64,{icon}"')
    page = replace_once(
        page,
        f'<script type="module" src="{js}"></script>',
        f'<script type="module">\n{script}</script>',
    )
    (web / "pkg" / out).write_text(page)


bundle("recover.html", "recover.js", "recover.html")
bundle("index.html", "app.js", "unravelrule.html")
