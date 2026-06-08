# Writing a template

The `template-checks` phase runs declarative templates against every discovered
host — a lightweight take on the nuclei model. Built-ins live in
`wraith/templates/`; add your own and point the run at them with
`--templates DIR`.

Templates are JSON (always supported) or YAML (if `pyyaml` is installed).

## Schema

```json
{
  "id": "git-config-exposure",
  "info": {
    "name": "Exposed .git/config",
    "severity": "high",
    "description": "Optional human-readable detail."
  },
  "requests": [
    {
      "method": "GET",
      "path": "/.git/config",
      "matchers-condition": "and",
      "matchers": [
        { "type": "status", "status": [200] },
        { "type": "word", "part": "body", "condition": "or",
          "words": ["[core]", "repositoryformatversion"] }
      ]
    }
  ]
}
```

- `severity`: `info` | `low` | `medium` | `high` | `critical`
- `requests`: tried in order; the first match reports and stops.
- `matchers-condition`: `and` (default) / `or` across a request's matchers.

## Matcher types

| type | keys | matches when |
|------|------|--------------|
| `status` | `status: [int]` | response code is in the list |
| `word` | `words: [str]`, `part`, `condition` | words appear in `part` |
| `regex` | `regex: [str]`, `part`, `condition` | patterns match `part` |
| `header` | `key`, `value` | header `key` contains `value` |

`part` is `body` (default), `header` or `all`. `condition` is `or` (default) or
`and` across the words/patterns of a single matcher.

## Tips

- Combine a `status` matcher with a `word`/`regex` matcher under
  `"matchers-condition": "and"` to keep false positives low.
- Keep `id` unique and kebab-case; it appears in the finding evidence.
