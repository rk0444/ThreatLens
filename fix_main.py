# Save this as E:\Project\ThreatLens\fix_main.py and run with venv python

file_path = r"E:\Project\ThreatLens\backend\main.py"

with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# The first (incomplete) block starts with this comment and ends just before the duplicate
FIRST_BLOCK_START = '''# ============================================================
# ADD THIS ENTIRE BLOCK to the end of backend/main.py
# ============================================================

COUNTRY_COORDS = {'''

# The second (complete) block starts with the same comment
SECOND_BLOCK_START = '''# ============================================================
# ADD THIS ENTIRE BLOCK to the end of backend/main.py
# ============================================================
 
COUNTRY_COORDS = {'''

# Verify both exist
if FIRST_BLOCK_START not in content:
    print("ERROR: Could not find first block marker. Aborting.")
    exit(1)

if SECOND_BLOCK_START not in content:
    print("ERROR: Could not find second block marker. Aborting.")
    exit(1)

# Find positions
first_pos = content.index(FIRST_BLOCK_START)
second_pos = content.index(SECOND_BLOCK_START)

if first_pos == second_pos:
    print("ERROR: Both markers point to same position — check delimiters.")
    exit(1)

print(f"First block starts at char {first_pos}")
print(f"Second block starts at char {second_pos}")

# Backup
with open(file_path + ".bak", "w", encoding="utf-8") as f:
    f.write(content)
print("Backup saved as main.py.bak")

# Keep everything before first block + everything from second block onward
fixed = content[:first_pos] + content[second_pos:]

# Remove the stray comment header from the kept block (optional cleanup)
fixed = fixed.replace(
    '''# ============================================================
# ADD THIS ENTIRE BLOCK to the end of backend/main.py
# ============================================================
 
COUNTRY_COORDS''',
    "COUNTRY_COORDS",
    1  # only first occurrence
)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(fixed)

print("Done. Verifying...")

# Verify only one get_attack_map remains
count = fixed.count("async def get_attack_map")
print(f"get_attack_map definitions found: {count}  (expected: 1)")

count2 = fixed.count("COUNTRY_COORDS = {")
print(f"COUNTRY_COORDS definitions found: {count2}  (expected: 1)")

# Verify the return statement exists in the kept function
if '"active_incidents": active_incident_count' in fixed:
    print("Return statement present: YES")
else:
    print("WARNING: Return statement not found!")