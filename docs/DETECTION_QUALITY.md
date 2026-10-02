# Detection quality

## Current status

Detection quality is not yet benchmarked. The test suite verifies selected behaviors and the narrow authorization test against a local fixture; it does not establish platform-wide precision, recall, false-positive rate, false-negative rate, or class coverage.

## Metrics planned when ground truth exists

For each supported vulnerability class, report counts for true positives, false positives, false negatives, and true negatives, plus precision, recall, verification success rate, reproduction success rate, evidence completeness, coverage, and request efficiency. Keep the fixture inventory and expected evidence versioned.

## Adversarial cases

Add benign reflection, generic errors, status changes, dynamic/noisy responses, false IDOR-like identifiers, unexploitable missing headers, safe redirects, rejected uploads, auth redirects, rate limits, and WAF blocks. A detector that cannot distinguish these cases must remain disabled or candidate-only.

Do not claim zero false positives or complete detection without benchmark results.
