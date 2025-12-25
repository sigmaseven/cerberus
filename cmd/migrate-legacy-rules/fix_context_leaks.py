with open('main_comprehensive_test.go', 'r') as f:
    lines = f.readlines()

# Fix the context leak issue by properly placing defer cancel()
output = []
i = 0
while i < len(lines):
    line = lines[i]
    output.append(line)
    
    # If we see WithCancel, add defer cancel() on next line with proper indentation
    if 'WithCancel' in line and 'cancel :=' in line:
        # Get indentation from current line
        indent = len(line) - len(line.lstrip())
        # Add defer cancel() with same indentation as the assignment
        output.append('\t' * (indent // 4) + 'defer cancel()\n')
        # Skip any existing defer cancel() on next lines to avoid duplicates
        i += 1
        while i < len(lines) and 'defer cancel()' in lines[i]:
            i += 1
        continue
    
    # Remove any misplaced defer cancel() that's not right after WithCancel
    if 'defer cancel()' in line:
        # Check if previous non-empty line has WithCancel
        prev_idx = len(output) - 2
        while prev_idx >= 0 and output[prev_idx].strip() == '':
            prev_idx -= 1
        if prev_idx >= 0 and 'WithCancel' not in output[prev_idx]:
            output.pop()  # Remove this defer cancel()
    
    i += 1

with open('main_comprehensive_test.go', 'w') as f:
    f.writelines(output)

print("Fixed context leaks")
