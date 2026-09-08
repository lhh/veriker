# FinSheet-style sweep — report

## Cells by status
| model | verified | abstained | unparseable | inconclusive | api_error | total | acc strict incl. abstentions |
|---|---|---|---|---|---|---|---|
| claude-opus-4.6-openrouter | 384 | 0 | 0 | 0 | 0 | 384 | 97.4% (374/384) |
| gemini-3.1-pro | 382 | 0 | 2 | 0 | 0 | 384 | 99.5% (380/382) |
| gpt-5.2 | 384 | 0 | 0 | 0 | 0 | 384 | 97.7% (375/384) |

## Accuracy by tier (strict / lenient), among concluded cells
| model | low | medium | high | very_high |
|---|---|---|---|---|
| claude-opus-4.6-openrouter | 100.0% (96/96) / len 100.0% (96/96) | 94.2% (113/120) / len 94.2% (113/120) | 97.9% (141/144) / len 99.3% (143/144) | 100.0% (24/24) / len 100.0% (24/24) |
| gemini-3.1-pro | 100.0% (96/96) / len 100.0% (96/96) | 98.3% (118/120) / len 98.3% (118/120) | 100.0% (142/142) / len 100.0% (142/142) | 100.0% (24/24) / len 100.0% (24/24) |
| gpt-5.2 | 100.0% (96/96) / len 100.0% (96/96) | 95.8% (115/120) / len 95.8% (115/120) | 97.2% (140/144) / len 98.6% (142/144) | 100.0% (24/24) / len 100.0% (24/24) |

## Accuracy by size (strict / lenient)
| model | S1 | S2 | S3 | S4 |
|---|---|---|---|---|
| claude-opus-4.6-openrouter | 100.0% (96/96) / len 100.0% (96/96) | 100.0% (96/96) / len 100.0% (96/96) | 97.9% (94/96) / len 97.9% (94/96) | 91.7% (88/96) / len 93.8% (90/96) |
| gemini-3.1-pro | 100.0% (96/96) / len 100.0% (96/96) | 100.0% (96/96) / len 100.0% (96/96) | 100.0% (96/96) / len 100.0% (96/96) | 97.9% (92/94) / len 97.9% (92/94) |
| gpt-5.2 | 100.0% (96/96) / len 100.0% (96/96) | 99.0% (95/96) / len 99.0% (95/96) | 97.9% (94/96) / len 97.9% (94/96) | 93.8% (90/96) / len 95.8% (92/96) |

## Accuracy by layout (strict / lenient)
| model | L1 | L2 | L3 | L4 | L5 | L6 |
|---|---|---|---|---|---|---|
| claude-opus-4.6-openrouter | 93.8% (60/64) / len 95.3% (61/64) | 98.4% (63/64) / len 98.4% (63/64) | 98.4% (63/64) / len 98.4% (63/64) | 96.9% (62/64) / len 96.9% (62/64) | 98.4% (63/64) / len 100.0% (64/64) | 98.4% (63/64) / len 98.4% (63/64) |
| gemini-3.1-pro | 98.4% (62/63) / len 98.4% (62/63) | 98.4% (62/63) / len 98.4% (62/63) | 100.0% (64/64) / len 100.0% (64/64) | 100.0% (64/64) / len 100.0% (64/64) | 100.0% (64/64) / len 100.0% (64/64) | 100.0% (64/64) / len 100.0% (64/64) |
| gpt-5.2 | 93.8% (60/64) / len 95.3% (61/64) | 96.9% (62/64) / len 96.9% (62/64) | 98.4% (63/64) / len 98.4% (63/64) | 100.0% (64/64) / len 100.0% (64/64) | 98.4% (63/64) / len 100.0% (64/64) | 98.4% (63/64) / len 98.4% (63/64) |

## Re-derivation: catch rate and false-alarm rate per arm
Catch = of WRONG answers, share the arm marked NOT_RE_DERIVED. False alarm = of CORRECT answers, share flagged. Strict = verifier tolerance; lenient = paper tier-1 (2.5% rel).

| model | acc strict | acc lenient | A catch (strict) | A false-alarm (strict) | A catch (lenient) | A false-alarm (lenient) | B catch (strict) | B false-alarm (strict) | B catch (lenient) | B false-alarm (lenient) |
|---|---|---|---|---|---|---|---|---|---|---|
| claude-opus-4.6-openrouter | 97.4% (374/384) | 97.9% (376/384) | 100.0% (10/10) | 0.0% (0/374) | 100.0% (8/8) | 0.5% (2/376) | 0.0% (0/10) | 1.1% (4/374) | 0.0% (0/8) | 1.1% (4/376) |
| gemini-3.1-pro | 99.5% (380/382) | 99.5% (380/382) | 100.0% (2/2) | 0.0% (0/380) | 100.0% (2/2) | 0.0% (0/380) | 0.0% (0/2) | 0.0% (0/380) | 0.0% (0/2) | 0.0% (0/380) |
| gpt-5.2 | 97.7% (375/384) | 98.2% (377/384) | 100.0% (9/9) | 0.0% (0/375) | 100.0% (7/7) | 0.5% (2/377) | 0.0% (0/9) | 0.5% (2/375) | 0.0% (0/7) | 0.5% (2/377) |

## Arm B catch rate by tier (strict wrong answers)
| model | low | medium | high | very_high |
|---|---|---|---|---|
| claude-opus-4.6-openrouter | n/a (0) | 0.0% (0/7) | 0.0% (0/3) | n/a (0) |
| gemini-3.1-pro | n/a (0) | 0.0% (0/2) | n/a (0) | n/a (0) |
| gpt-5.2 | n/a (0) | 0.0% (0/5) | 0.0% (0/4) | n/a (0) |

## Split of strict-wrong answers
| model | tier | wrong | hallucinated_operand | arithmetic | malformed_derivation | selection | uncaught | op matches question |
|---|---|---|---|---|---|---|---|---|
| claude-opus-4.6-openrouter | low | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| claude-opus-4.6-openrouter | medium | 7 | 0 | 0 | 0 | 7 | 0 | 100.0% (7/7) |
| claude-opus-4.6-openrouter | high | 3 | 0 | 0 | 0 | 3 | 0 | 100.0% (3/3) |
| claude-opus-4.6-openrouter | very_high | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| claude-opus-4.6-openrouter | ALL | 10 | 0 | 0 | 0 | 10 | 0 | 100.0% (10/10) |
| gemini-3.1-pro | low | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| gemini-3.1-pro | medium | 2 | 0 | 0 | 0 | 2 | 0 | 100.0% (2/2) |
| gemini-3.1-pro | high | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| gemini-3.1-pro | very_high | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| gemini-3.1-pro | ALL | 2 | 0 | 0 | 0 | 2 | 0 | 100.0% (2/2) |
| gpt-5.2 | low | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| gpt-5.2 | medium | 5 | 0 | 0 | 0 | 5 | 0 | 100.0% (5/5) |
| gpt-5.2 | high | 4 | 0 | 0 | 0 | 4 | 0 | 100.0% (4/4) |
| gpt-5.2 | very_high | 0 | 0 | 0 | 0 | 0 | 0 | n/a (0) |
| gpt-5.2 | ALL | 9 | 0 | 0 | 0 | 9 | 0 | 100.0% (9/9) |

## Hallucinated operands among strict-wrong answers, S4 files
- claude-opus-4.6-openrouter: 0.0% (0/8)
- gemini-3.1-pro: 0.0% (0/2)
- gpt-5.2: 0.0% (0/6)

## Unparseable on S4
- claude-opus-4.6-openrouter: 0.0% (0/96)
- gemini-3.1-pro: 2.1% (2/96)
- gpt-5.2: 0.0% (0/96)

## Tokens (sum over cells with usage)
| model | cells | input tokens | output tokens | max input |
|---|---|---|---|---|
| claude-opus-4.6-openrouter | 384 | 1,307,082 | 145,601 | 7,824 |
| gemini-3.1-pro | 384 | 1,575,824 | 91,165 | 9,648 |
| gpt-5.2 | 384 | 1,226,346 | 144,174 | 7,384 |

## Uncaught strict-wrong answers (0)
