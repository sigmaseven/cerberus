#!/usr/bin/env python3
import re

with open('main.go', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the duplicate if false block
content = re.sub(r'\n\t// Replace old panic handler\n\tif false \{\n\t\tif p := recover\(\); p != nil \{\n\t\t\tif rbErr := tx\.Rollback\(\); rbErr != nil \{\n\t\t\t\tfmt\.Fprintf\(os\.Stderr, "Warning: failed to rollback transaction after panic: %v\n", rbErr\)\n\t\t\t\}\n\t\t\tpanic\(p\) // Re-panic after rollback\n\t\t\}\n\t\}\(\)\n', '\n', content)

with open('main.go', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed syntax error")
