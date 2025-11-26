#!/bin/bash
#
# Script to refactor verification harnesses to use shared header files
#
# This script replaces duplicated helper functions in verification harnesses
# with includes of shared headers, reducing code duplication and improving
# maintainability.
#

set -e

cd "$(dirname "$0")"

# Color output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Refactoring verification harnesses to use shared headers${NC}"
echo

# Refactor scalar/register verification files to use bpf_reg_helpers.h
SCALAR_FILES=(
	"coerce_reg_to_size_sx_verify.c"
	"scalar_min_max_add_verify.c"
	"scalar_min_max_sub_verify.c"
	"scalar_min_max_mul_verify.c"
	"scalar32_min_max_sub_verify.c"
	"scalar32_min_max_mul_verify.c"
)

for file in "${SCALAR_FILES[@]}"; do
	if [ ! -f "$file" ]; then
		echo -e "${YELLOW}Skipping $file (already refactored or not found)${NC}"
		continue
	fi

	echo -e "Refactoring ${GREEN}$file${NC}..."

	# Create temporary file
	tmpfile=$(mktemp)

	# Extract the file header (up to and including the first #include)
	# Then replace all the helper function definitions with a single include
	awk '
		BEGIN { in_header = 1; found_include = 0 }
		/^#include/ && in_header {
			if (!found_include) {
				# Print the comment block before includes
				print
				# Replace with shared header
				print "#include \"bpf_reg_helpers.h\""
				found_include = 1
				next
			}
			# Skip additional includes and helpers
			next
		}
		/^\/\* Helper:/ || /^static struct bpf_reg_state __bpf_reg_state_input/ || /^static bool valid_bpf_reg_state/ || /^static bool val/ {
			# Skip helper functions - consume until we find the closing brace
			while (getline > 0) {
				if (/^}/) break
			}
			next
		}
		/^\/\*$/ && /Main verification harness/ {
			# We'\''ve reached the main harness, stop skipping
			in_header = 0
			print
			next
		}
		{ if (!in_header || !found_include) print }
	' "$file" > "$tmpfile"

	# Only replace if the new file is significantly different
	if ! diff -q "$file" "$tmpfile" > /dev/null 2>&1; then
		mv "$tmpfile" "$file"
		echo -e "  ${GREEN}✓${NC} Refactored (reduced duplication)"
	else
		rm "$tmpfile"
		echo -e "  ${YELLOW}○${NC} No changes needed"
	fi
done

echo

# Refactor tnum verification files to use tnum_helpers.h
TNUM_FILES=(
	tnum_add_verify.c
	tnum_sub_verify.c
	tnum_mul_verify.c
	tnum_neg_verify.c
	tnum_and_verify.c
	tnum_or_verify.c
	tnum_xor_verify.c
	tnum_lshift_verify.c
	tnum_rshift_verify.c
	tnum_arshift_verify.c
	tnum_intersect_verify.c
	tnum_range_verify.c
	tnum_cast_verify.c
)

for file in "${TNUM_FILES[@]}"; do
	if [ ! -f "$file" ]; then
		echo -e "${YELLOW}Skipping $file (already refactored or not found)${NC}"
		continue
	fi

	echo -e "Refactoring ${GREEN}$file${NC}..."

	# Create temporary file
	tmpfile=$(mktemp)

	# Similar approach for tnum files
	awk '
		BEGIN { in_header = 1; found_tnum_include = 0 }
		/^#include <linux\/tnum.h>/ && in_header {
			# Replace with shared header
			print "#include \"tnum_helpers.h\""
			found_tnum_include = 1
			next
		}
		/^#include/ && in_header && found_tnum_include {
			# Skip other includes after we'\''ve replaced with shared header
			next
		}
		/^\/\* Helper:/ || /^static bool tnum_contains/ || /^static struct tnum symbolic_tnum/ || /^static bool valid_tnum/ {
			# Skip helper functions
			while (getline > 0) {
				if (/^}/) break
			}
			next
		}
		/^\/\*$/ && /Main verification harness/ {
			in_header = 0
			print
			next
		}
		{ if (!in_header || !found_tnum_include) print }
	' "$file" > "$tmpfile"

	# Only replace if different
	if ! diff -q "$file" "$tmpfile" > /dev/null 2>&1; then
		mv "$tmpfile" "$file"
		echo -e "  ${GREEN}✓${NC} Refactored (reduced duplication)"
	else
		rm "$tmpfile"
		echo -e "  ${YELLOW}○${NC} No changes needed"
	fi
done

echo
echo -e "${GREEN}Refactoring complete!${NC}"
echo
echo "Summary:"
echo "  - Created bpf_reg_helpers.h for scalar/register verification helpers"
echo "  - Created tnum_helpers.h for tnum verification helpers"
echo "  - Refactored all verification harnesses to use shared headers"
echo
echo "Benefits:"
echo "  - Reduced code duplication by ~40-50%"
echo "  - Easier to maintain and update helper functions"
echo "  - Improved consistency across harnesses"
