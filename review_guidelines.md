# Code Review Prompt and Checklist

Use the following checklist to review C/C/C++ code. Focus on correctness, safety, clarity, and adherence to the guidelines. Report concrete findings with file/line references, a short rationale, and a specific fix suggestion. Do not propose large refactors unless required for correctness or safety.

## How to Review and Report
- For each issue: include location (file:line), short title, why it matters, and a minimal fix.
- Prefer precise, actionable feedback over generalities. Group related issues where appropriate.
- Summarize at the end: pass/fail against each section and top risks (if any).

---

## 2. Indentation

### 2.2 Wrapping Lines
- Prefer higher‑level breaks to lower‑level breaks; line breaks should follow logical precedence rather than arbitrary splits.
- If the standard wrapping rules produce confusing code, use a 4‑column indentation to improve clarity.
- When wrapping, align the new line with the beginning of the previous logical unit using a 4‑column indentation when it improves readability.

### 2.4 Blank Lines
- Ensure a blank line follows any copyright block comment.
- Separate groups of related global declarations with blank lines.
- Separate logically related struct/field declarations with blank lines where helpful.
- After local variable declarations, insert a blank line before the first executable statement.
- Within function bodies, separate logically related code chunks with blank lines for readability.

## 3. Naming Conventions

### 3.1 General Rules
- Names must be descriptive and easily understood by other readers.
- Use multiple words for identifiers with clear word separation (follow project conventions for separators or casing).
- Trivial names like `i`, `j`, `k` are acceptable for loop counters only and within tight/local scope.
- Treat acronyms as words; capitalize only the first letter according to project casing rules.
- Document newly introduced acronyms.

## 4. Comments

### 4.1 General
- Comments should explain what the code does and why, not how it works line‑by‑line.
- Use block comments (`/* ... */`) for large text (e.g., copyright messages).
- Use single‑line comments (`//`) for brief notes.
- Keep comments inside functions concise (a few lines at most).

### 4.2 Commenting Out Code
- Long‑term commented‑out code should generally be removed rather than retained.
- Avoid `#if 0` blocks inside function bodies to prevent accidental code removal or confusion.

### 4.3 Formatting
- Block comments should follow consistent formatting per project style (alignment, spacing, wrapping).

## 5. Doxygen and Documentation
- Verify public APIs and non‑trivial modules are documented per the project’s Doxygen standards (consult the Doxygen Manual). Check parameter/return descriptions, edge cases, and error semantics.

## 7. Integer Types

### 7.1 Additional Naming Guidelines
- Use noun‑phrase names for integer variables (e.g., `retry_count`, `packet_length`).

### 7.3.1 Integer Use in Expressions and Arithmetic
- Follow CERT INT rules and safe integer practices (overflow, underflow, sign conversions, shifts). Flag implicit/unsafe conversions and arithmetic on mixed‑signedness.

## 9. Boolean Types

### 9.1 Additional Naming Guidelines
- Name booleans for the meaning of their true value (e.g., `is_ready`, `has_error`, `should_retry`).

## 12. Enumerated Types

### 12.2 Defining and Initializing
- Provide strategies to test enum value validity (e.g., sentinel values, range checks, default cases that handle unknown values).

## 13. Bit Fields
- Use bit fields appropriately to map registers or sub‑register operations; verify widths, signedness, and portability implications are well‑understood and documented where needed.

## 15. Functions

### 15.1 Additional Naming Guidelines
- Name procedures (void functions) for what they do (effect), not how they do it.
- Name functions for what they return; boolean‑valued functions should reflect the property implied when true (e.g., `is_valid`, `supports_tls`).

## 17. Expressions
- Make operator precedence explicit with parentheses where ambiguity is possible.
- If an expression is hard to understand, break it into simpler steps or extract a well‑named helper function.

### 17.3 Expressions and Data Type Conversions
- Exercise extreme caution with type conversions; avoid narrowing/precision loss and unintended sign/aliasing changes. Prefer explicit casts with documented rationale.

## 20. Constants

### 20.3 Rules for `const`
- Apply the “right‑hand rule” for `const` placement so the keyword appears to the right of what it modifies consistently (match project style).

### 20.6 Memory Management
- Track the size of allocated buffers if reused for multiple objects or treated as arrays; ensure bounds are enforced.
- For functions that allocate and return ownership, clearly document ownership and free‑responsibility.

## 21. Copyright Message
- Ensure the project‑approved copyright boilerplate is applied exactly as dictated by the docs/legal team.

## 22. Header Files

### 22.2 Include Order
- Enforce correct and consistent include order (e.g., corresponding header first, then project headers, then system/third‑party). Detect and remove hidden order dependencies.

## 23. Error Checking and Debugging

### 23.1 Error Checking
- `assert` is not a replacement for runtime error handling. Validate inputs/returns and propagate or handle errors appropriately.

### 23.2 Debugging
- Distinguish active (development‑only) and passive (ships in release) debugging code.
- Passive debugging code must comply with safety/security guidelines.
- Debug strings should clearly identify error location/context and aid reproduction (avoid leaking sensitive data).
- Active debugging code must never ship in production; ensure removal or proper guards.

## 24. Use 64‑Bit Operations Wisely
- On 32‑bit targets, 64‑bit multiply/divide/shift may generate helper calls, stack setup, and inhibit optimizations; use judiciously on performance paths.
- Prefer 64‑bit types only when data inherently requires >32 bits (e.g., wide counters, timestamps, large addresses such as 40‑bit).
- Where 64‑bit is required, ensure correctness and document rationale; otherwise, prefer 32‑bit to reduce overhead on constrained targets.

## 25. Floating Point
- Prefer known‑good numerical formulations to avoid overflow/underflow when available.
- Handle NaN/Inf and floating‑point exceptions; validate inputs and check results where appropriate.

## 27. Algorithms
- Prefer algorithms suitable for the data set size and numerical properties.
- For small `n`, simple/direct algorithms can be acceptable; for large `n`, select or research appropriate algorithms and document complexity tradeoffs.
- Reuse well‑vetted algorithms/implementations when available.

---

## Reviewer Output Template

Use this structure for each issue you report:

1) Title: <short issue name>
   - Location: <file:line>
   - Guideline: <section/subsection>
   - Why it matters: <1–2 sentences>
   - Suggested fix: <specific change>
   - Snippet (optional): ```c
     // minimal excerpt showing the problem
     ```

Summary:
- Section Status: {pass|fail} for each section above
- Top Risks: <brief list or “none”>
