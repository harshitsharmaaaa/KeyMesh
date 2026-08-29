# TSS Runtime Review Checklist

- [ ] Is there a supported participant-level runtime API?
- [ ] Are round transitions externally driven or helper-only?
- [ ] Is message ordering defined?
- [ ] Are disconnect and retry semantics defined?
- [ ] Can participant state survive restart safely?
- [ ] Is concurrency isolation documented?
- [ ] Are serialization formats canonical and documented?
- [ ] Are transport secrets separate from threshold shares?
- [ ] Does the coordinator remain untrusted for signing authority?
- [ ] Are only public/stable APIs used?
- [ ] Is the license compatible with the intended distribution model?
- [ ] Is the platform support sufficient for Linux CI and deployment?
