import re

from loguru import logger

from base_classes.pdg_node import PDGNode
from llm import llm_inspect_file_content
from npm_pipeline.handlers.file_handler import _is_binary_content

DEFAULT_TRUNCATE_HEAD = 3000
DEFAULT_TRUNCATE_TAIL = 2000
SNIPPET_CONTEXT_LINES = 2
MAX_MIDDLE_SNIPPETS = 10
MAX_MIDDLE_CHARS = 2000
MAX_INSPECTED_FILES = 10


def retrieve_and_inspect_files(
    files_to_inspect: list[dict],
    node_map: dict[int, PDGNode],
    truncate_head: int = DEFAULT_TRUNCATE_HEAD,
    truncate_tail: int = DEFAULT_TRUNCATE_TAIL,
) -> list[dict]:
    """Retrieve large_text file content from PDGNode by node_id, truncate it, and pass it to
    the LLM to generate a summary.

    When the number of ``files_to_inspect`` entries exceeds :data:`MAX_INSPECTED_FILES`,
    only the first ``MAX_INSPECTED_FILES`` entries are kept; the remaining files do not appear in the returned result,
    but the LLM can infer their existence from ``file_io_records`` metadata.
    """
    if len(files_to_inspect) > MAX_INSPECTED_FILES:
        extra = len(files_to_inspect) - MAX_INSPECTED_FILES
        logger.warning(
            f"[Dynamic] {extra} large_text files skipped from inspection "
            f"(cap={MAX_INSPECTED_FILES})"
        )
        files_to_inspect = files_to_inspect[:MAX_INSPECTED_FILES]

    results: list[dict] = []
    for spec in files_to_inspect:
        file_path = spec.get("file_path", "")
        operation = spec.get("operation", "")
        nid = spec.get("node_id")

        if nid is None or nid not in node_map:
            logger.warning(
                f"[RAG] No PDGNode found for node_id={nid}, file={file_path} ({operation})"
            )
            results.append(
                {
                    "file_path": file_path,
                    "operation": operation,
                    "node_id": nid,
                    "status": "content_unavailable",
                }
            )
            continue

        raw = node_map[nid].get_large_file_content(file_path, operation)
        if not raw:
            logger.warning(f"[RAG] No bound content for {file_path} ({operation}) on node {nid}")
            results.append(
                {
                    "file_path": file_path,
                    "operation": operation,
                    "node_id": nid,
                    "status": "content_unavailable",
                }
            )
            continue

        content_str = str(raw)

        if _is_binary_content(content_str):
            results.append(
                {
                    "file_path": file_path,
                    "operation": operation,
                    "node_id": nid,
                    "status": "binary_content",
                }
            )
            continue

        truncated = _truncate_content(content_str, truncate_head, truncate_tail)

        inspection = llm_inspect_file_content(
            {"file_path": file_path, "operation": operation, "content": truncated}
        )
        if inspection:
            results.append(
                {
                    "file_path": file_path,
                    "operation": operation,
                    "node_id": nid,
                    "content_summary": inspection.get("content_summary", ""),
                    "security_signals": inspection.get("security_signals", []),
                }
            )
        else:
            results.append(
                {
                    "file_path": file_path,
                    "operation": operation,
                    "node_id": nid,
                    "status": "inspection_failed",
                }
            )

    return results


def _truncate_content(content: str, head: int, tail: int) -> str:
    """Security-signal-aware truncation: keep the head and tail, and extract security-relevant snippets from the middle segment."""
    if len(content) <= head + tail:
        return content

    middle = content[head : len(content) - tail] if tail else content[head:]
    security_snippets = _extract_security_snippets(middle)

    parts = [content[:head]]
    if security_snippets:
        parts.append(
            f"\n... [middle truncated, {len(content)} chars total, "
            f"extracted {len(security_snippets)} security-relevant fragments] ...\n"
        )
        parts.append("\n---\n".join(security_snippets))
        parts.append("\n... [end of extracted fragments] ...\n")
    else:
        parts.append(
            f"\n... [truncated, {len(content)} chars total, "
            f"no security patterns found in middle] ...\n"
        )
    if tail:
        parts.append(content[-tail:])
    return "".join(parts)


_SECURITY_PATTERNS = re.compile(
    r"|".join(
        [
            # Network / external access.
            r"https?://[^\s\"'`\]}>){,]+",
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b",
            r"\b(?:XMLHttpRequest|fetch|axios|request)\s*[.(]",
            r"\b(?:window\.)?fetch\s*\(",
            r"\b(?:https?|http)\.(?:get|request)\s*\(",
            r"\b(?:\$|jQuery)\.(?:get|post|ajax)\s*\(",
            r"\bnew\s+WebSocket\s*\(",
            # Command execution / subprocess.
            r"\bchild_process\b",
            r"\b(?:eval|exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(",
            r"\b(?:curl|wget|nc|ncat|bash|sh|powershell)\b",
            r"\bnew\s+Function\s*\(",
            # File-system operations.
            r"\bfs\.(?:read(?:File(?:Sync)?|dir(?:Sync)?|linkSync|Link)?|"
            r"write(?:File(?:Sync)?)?|append(?:File(?:Sync)?)?|"
            r"createReadStream|createWriteStream|"
            r"open(?:Sync)?|stat(?:Sync)?|access(?:Sync)?|"
            r"exists(?:Sync)?|unlink(?:Sync)?|rm(?:Sync)?|glob(?:Sync)?)\s*\(",
            r"\bfs/promises\.(?:readFile|writeFile|appendFile|readdir|"
            r"readlink|open|rm|unlink|glob)\s*\(",
            # Sensitive paths.
            r"/etc/(?:passwd|shadow|hosts)|~/\.ssh|\.env\b",
            # Credentials / secrets.
            r"\b(?:password|passwd|secret|token|api[_-]?key|credential)s?\b",
            r"\b(?:api[_-]?key|secret|token|password)\s*=\s*[\"'][^\"']+[\"']",
            r"\bprocess\.env\b",
            # Encoding / obfuscation.
            r"\b(?:atob|btoa|Buffer\.from)\s*\(",
            r"[A-Za-z0-9+/]{40,}={0,2}",
            r"(?:\\x[0-9a-fA-F]{2}){4,}",
            r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}",
            # Browser file-reading APIs.
            r"\b(?:readAsText|readAsArrayBuffer|readAsDataURL)\s*\(",
        ]
    ),
    re.IGNORECASE,
)


def _extract_security_snippets(middle_text: str) -> list[str]:
    """Scan the middle segment line by line for security-relevant patterns and return snippets made from matching lines plus context."""
    if not middle_text:
        return []

    lines = middle_text.split("\n")
    hit_line_indices: set[int] = set()
    for i, line in enumerate(lines):
        if _SECURITY_PATTERNS.search(line):
            hit_line_indices.add(i)

    if not hit_line_indices:
        return []

    ranges: list[tuple[int, int]] = []
    for idx in sorted(hit_line_indices):
        start = max(0, idx - SNIPPET_CONTEXT_LINES)
        end = min(len(lines) - 1, idx + SNIPPET_CONTEXT_LINES)
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], end)
        else:
            ranges.append((start, end))

    snippets: list[str] = []
    total_chars = 0
    for start, end in ranges:
        if len(snippets) >= MAX_MIDDLE_SNIPPETS:
            break
        fragment = "\n".join(lines[start : end + 1])
        if total_chars + len(fragment) > MAX_MIDDLE_CHARS and snippets:
            break
        snippets.append(fragment)
        total_chars += len(fragment)

    return snippets
