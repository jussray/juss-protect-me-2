# Production browser runtime compatibility

Exact-head failure evidence: GitHub run 45366182181, job 138348367285, commit 28eea7ba0262498497d36485bad4691301de8ca9. The example Shield browser test passed (1/1). The production Worker did not start because the installed Wrangler 4.118.0 runtime supports compatibility dates only through 2026-08-06; the production Worker requires 2026-10-15. The production smoke suite was not executed in that run. Report upload succeeded. Source verification also passed.

Restore the historical production Playwright launcher (Wrangler 4.151.0, explicitly version-pinned), whose configuration was present at 10974aed34f7806936740630c71b8e37ab12e50d, where job 133019929869 passed nine production browser tests and one example test. Keep the production compatibility date, all assertions and the mandatory aggregate gate unchanged. Current runtime acceptance requires a new successful CI run; historical success alone is not acceptance of the new head.
