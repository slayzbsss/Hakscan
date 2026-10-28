# Template Syntax Reference

Hakscan templates are JSON files. Community YAML templates (HTTP subset) are
also supported. Two JSON kinds exist.

## kind: http

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | string | `"http"` |
| `name` | string | human-readable finding title |
| `severity` | string | info \| low \| medium \| high \| critical |
| `description` | string | optional |
| `path` | string | request path, relative to the target origin |
| `method` | string | HTTP method (default `GET`) |
| `matchers-condition` | string | `and` \| `or` (default `and` for JSON) |
| `matchers` | array | list of matchers (below) |

### Matchers

| `type` | Fields | Meaning |
| --- | --- | --- |
| `status` | `values: [int]` | response status is in the list |
| `word` | `values: [string]`, `part`, `all` | substring(s) present |
| `regex` | `values: [string]`, `part` | pattern(s) match |

- `part`: `body` (default) or `header`.
- `word.all`: `true` = all values required, `false`/absent = any.

### Example

```json
{
  "kind": "http",
  "name": "Exposed phpinfo()",
  "severity": "medium",
  "path": "/phpinfo.php",
  "matchers": [
    {"type": "word", "part": "body", "values": ["phpinfo()", "PHP Version"], "all": true}
  ]
}
```

## kind: secret

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | string | `"secret"` |
| `name` | string | finding title |
| `severity` | string | severity level |
| `regex` | string | RE2 pattern; a match is reported |

```json
{"kind": "secret", "name": "Google API key", "severity": "high",
 "regex": "AIza[0-9A-Za-z\\-_]{35}"}
```

## Community YAML (HTTP subset)

`http[0]` with `path`, `method`, `matchers` of type `word`/`status`/`regex`,
`matchers-condition`, `part`, `condition`, `case-insensitive`, `negative`.
`{{BaseURL}}` and `{{Hostname}}` are substituted. Templates using `raw`
requests, `dsl` matchers, extractors or multi-step flows are skipped.
