# Sigma rules

Place official Sigma YAML rules here or set `SIGMA_RULES_PATH`. Vrin_TI uses
`yaml.safe_load`, preserves official `logsource`, `detection`, `condition`,
false-positive, severity, and `attack.t####` metadata, and does not invent or
execute a custom rule language. Rule deployment remains an analyst-controlled
SOC operation.
