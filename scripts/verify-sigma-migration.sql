-- ============================================================================
-- SIGMA Migration Verification Queries
-- ============================================================================
-- Purpose: Verify that all rules have been migrated to SIGMA format
-- Requirements:
--   - All rules must have type='sigma'
--   - All rules must have non-empty sigma_yaml field
--   - All rules must have empty/null conditions field (legacy)
--   - No rules should have non-empty conditions field
--
-- Usage:
--   sqlite3 data/cerberus.db < scripts/verify-sigma-migration.sql
--
-- Exit codes:
--   0 = All verification checks passed (no legacy rules found)
--   1 = Verification failed (legacy rules exist)
-- ============================================================================

.mode column
.headers on
.nullvalue NULL

-- ============================================================================
-- 1. Count total rules by type
-- ============================================================================
.print ""
.print "============================================================"
.print "1. RULE TYPE DISTRIBUTION"
.print "============================================================"

SELECT
    type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM rules), 2) as percentage
FROM rules
GROUP BY type
ORDER BY count DESC;

-- ============================================================================
-- 2. Verify all rules are SIGMA type
-- ============================================================================
.print ""
.print "============================================================"
.print "2. NON-SIGMA RULES (SHOULD BE EMPTY)"
.print "============================================================"

SELECT
    id,
    type,
    name,
    enabled
FROM rules
WHERE LOWER(TRIM(type)) != 'sigma'
ORDER BY id;

-- ============================================================================
-- 3. Verify all rules have sigma_yaml populated
-- ============================================================================
.print ""
.print "============================================================"
.print "3. RULES WITH EMPTY SIGMA_YAML (SHOULD BE EMPTY)"
.print "============================================================"

SELECT
    id,
    type,
    name,
    CASE
        WHEN sigma_yaml IS NULL THEN 'NULL'
        WHEN TRIM(sigma_yaml) = '' THEN 'EMPTY'
        ELSE 'OTHER'
    END as sigma_yaml_status,
    enabled
FROM rules
WHERE sigma_yaml IS NULL OR TRIM(sigma_yaml) = ''
ORDER BY id;

-- ============================================================================
-- 4. Verify all rules have empty/null conditions field (legacy)
-- ============================================================================
.print ""
.print "============================================================"
.print "4. RULES WITH LEGACY CONDITIONS (SHOULD BE EMPTY)"
.print "============================================================"

SELECT
    id,
    type,
    name,
    CASE
        WHEN conditions IS NULL THEN 'NULL'
        WHEN TRIM(conditions) = '' THEN 'EMPTY'
        WHEN conditions = '[]' THEN 'EMPTY_ARRAY'
        ELSE 'POPULATED'
    END as conditions_status,
    LENGTH(conditions) as conditions_length,
    enabled
FROM rules
WHERE conditions IS NOT NULL
  AND TRIM(conditions) != ''
  AND conditions != '[]'
ORDER BY id;

-- ============================================================================
-- 5. Summary statistics
-- ============================================================================
.print ""
.print "============================================================"
.print "5. MIGRATION SUMMARY"
.print "============================================================"

SELECT
    'Total Rules' as metric,
    COUNT(*) as count
FROM rules

UNION ALL

SELECT
    'SIGMA Rules' as metric,
    COUNT(*) as count
FROM rules
WHERE LOWER(TRIM(type)) = 'sigma'

UNION ALL

SELECT
    'Non-SIGMA Rules' as metric,
    COUNT(*) as count
FROM rules
WHERE LOWER(TRIM(type)) != 'sigma'

UNION ALL

SELECT
    'Rules with sigma_yaml' as metric,
    COUNT(*) as count
FROM rules
WHERE sigma_yaml IS NOT NULL AND TRIM(sigma_yaml) != ''

UNION ALL

SELECT
    'Rules with empty sigma_yaml' as metric,
    COUNT(*) as count
FROM rules
WHERE sigma_yaml IS NULL OR TRIM(sigma_yaml) = ''

UNION ALL

SELECT
    'Rules with legacy conditions' as metric,
    COUNT(*) as count
FROM rules
WHERE conditions IS NOT NULL
  AND TRIM(conditions) != ''
  AND conditions != '[]'

UNION ALL

SELECT
    'Rules with empty conditions' as metric,
    COUNT(*) as count
FROM rules
WHERE conditions IS NULL
   OR TRIM(conditions) = ''
   OR conditions = '[]';

-- ============================================================================
-- 6. Sample SIGMA YAML content (first rule)
-- ============================================================================
.print ""
.print "============================================================"
.print "6. SAMPLE SIGMA YAML (FIRST RULE)"
.print "============================================================"

SELECT
    id,
    name,
    SUBSTR(sigma_yaml, 1, 500) || '...' as sigma_yaml_preview
FROM rules
WHERE sigma_yaml IS NOT NULL AND TRIM(sigma_yaml) != ''
LIMIT 1;

-- ============================================================================
-- 7. Verification verdict
-- ============================================================================
.print ""
.print "============================================================"
.print "7. VERIFICATION VERDICT"
.print "============================================================"

SELECT
    CASE
        WHEN (
            -- All rules are SIGMA type
            (SELECT COUNT(*) FROM rules WHERE LOWER(TRIM(type)) != 'sigma') = 0
            AND
            -- All rules have sigma_yaml populated
            (SELECT COUNT(*) FROM rules WHERE sigma_yaml IS NULL OR TRIM(sigma_yaml) = '') = 0
            AND
            -- All rules have empty conditions (legacy)
            (SELECT COUNT(*) FROM rules WHERE conditions IS NOT NULL AND TRIM(conditions) != '' AND conditions != '[]') = 0
        ) THEN 'PASS: All rules successfully migrated to SIGMA format'
        ELSE 'FAIL: Migration incomplete - see details above'
    END as verdict;

-- ============================================================================
-- 8. Exit with appropriate code
-- ============================================================================
.print ""
.print "============================================================"

-- This will be parsed by the shell script to determine exit code
-- If any legacy rules exist, output will show failures above
