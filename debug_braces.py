
try:
    with open('/Users/ivanhuerta/Documents/chronos_antigravity/static/script.js', 'r') as f:
        lines = f.readlines()
except FileNotFoundError:
    print("File not found")
    exit(1)

balance = 0
paren_balance = 0

for i, line in enumerate(lines):
    # Only count code, ignore comments (basic check)
    clean_line = line.split('//')[0] 
    
    for char in clean_line:
        if char == '{': balance += 1
        else:
            if char == '}': balance -= 1
        if char == '(': paren_balance += 1
        else:
            if char == ')': paren_balance -= 1
    
    if balance < 0:
        print(f'Line {i+1}: Braces went negative! (Excess })')
        break
    if paren_balance < 0:
        print(f'Line {i+1}: Parentheses went negative! (Excess ))')
        break

print(f'Final Brace Balance: {balance}')
print(f'Final Paren Balance: {paren_balance}')

if balance > 0:
    print("MISSING CLOSING BRACES '}'")
if paren_balance > 0:
    print("MISSING CLOSING PARENTHESES ')'")
