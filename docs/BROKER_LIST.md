# TraceBurn Broker List

> **Note:** Opt-out URLs and processes change. Verify before automating. PRs welcome.

> **Live test finding:** Spokeo CAPTCHA confirmed 2026-04-01 — downgraded Tier 1 → Tier 3 (Manual).

---

## Broker Reference Table

| Broker | Domain | Tier | Region | CAPTCHA | Phone Verify | Email Verify | Account Req | Re-list Risk | Timeline | Opt-Out URL | Last Verified |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Spokeo | spokeo.com | 3 (Manual) | US | Yes | No | Yes | No | High | 3 days | https://www.spokeo.com/optout | 2026-04-01 |
| Whitepages | whitepages.com | 3 (Manual) | US | No | Yes | No | No | High | 1 day | https://www.whitepages.com/suppression-requests | 2026-04-01 |
| Intelius | intelius.com | 1 (Playwright) | US | No | No | Yes | No | Medium | 3 days | https://www.intelius.com/opt-out | 2026-04-01 |
| BeenVerified | beenverified.com | 1 (Playwright) | US | No | No | Yes | No | Medium | 2 days | https://www.beenverified.com/app/optout/search | 2026-04-01 |
| MyLife | mylife.com | 1 (Playwright) | US | No | No | No | No | High | 30 days | https://www.mylife.com/ccpa/index.pubview | 2026-04-01 |
| Radaris | radaris.com | 3 (Manual) | US | No | No | No | Yes | High | 3 days | https://radaris.com/control/privacy | 2026-04-01 |
| FamilyTreeNow | familytreenow.com | 3 (Manual) | US | Yes | No | No | No | High | 1 day | https://www.familytreenow.com/optout | 2026-04-01 |
| PeopleFinders | peoplefinders.com | 1 (Playwright) | US | No | No | No | No | Medium | 2 days | https://www.peoplefinders.com/opt-out | 2026-04-01 |
| ZabaSearch | zabasearch.com | 2 (Email) | US | No | No | No | No | Low | 30 days | https://www.zabasearch.com | 2026-04-01 |
| TruthFinder | truthfinder.com | 1 (Playwright) | US | No | No | Yes | No | Medium | 2 days | https://www.truthfinder.com/opt-out/ | 2026-04-01 |
| InstantCheckmate | instantcheckmate.com | 1 (Playwright) | US | No | No | Yes | No | Medium | 2 days | https://www.instantcheckmate.com/opt-out/ | 2026-04-01 |
| CheckPeople | checkpeople.com | 1 (Playwright) | US | No | No | No | No | Medium | 2 days | https://checkpeople.com/opt-out | 2026-04-01 |
| PeopleLooker | peoplelooker.com | 1 (Playwright) | US | No | No | Yes | No | Medium | 2 days | https://www.peoplelooker.com/opt-out | 2026-04-01 |
| USSearch | ussearch.com | 3 (Manual) | US | No | Yes | No | No | Low | 30 days | https://www.ussearch.com/consumer/ala/landing/ | 2026-04-01 |
| Acxiom | acxiom.com | 1 (Playwright) | US | No | No | No | No | Medium | 37 days | https://isapps.acxiom.com/optout/optout.aspx | 2026-04-01 |
| LexisNexis | lexisnexis.com | 3 (Manual) | US | No | No | No | No | Medium | 60 days | https://optout.lexisnexis.com/ | 2026-04-01 |
| Epsilon | epsilon.com | 1 (Playwright) | US | No | No | No | No | Medium | 45 days | https://www.epsilon.com/us/privacy-policy | 2026-04-01 |
| Oracle Data Cloud | datacloudoptout.oracle.com | 1 (Playwright) | Global | No | No | No | No | Medium | 45 days | https://datacloudoptout.oracle.com/ | 2026-04-01 |
| Experian Marketing | experian.com | 1 (Playwright) | US | No | No | No | No | Medium | 37 days | https://www.experian.com/privacy/center.html | 2026-04-01 |
| Equifax Marketing | equifax.com | 1 (Playwright) | US | No | No | No | No | Medium | 45 days | https://www.equifax.com/personal/privacy/ | 2026-04-01 |

---

## Tier Explanations

| Tier | Label | Description |
|---|---|---|
| 1 | Playwright | Fully automated removal via headless browser (Playwright). TraceBurn submits the opt-out form on your behalf with no manual interaction required. |
| 2 | Email | Opt-out is handled by sending a formatted removal request email via SMTP. TraceBurn generates and sends the email automatically. |
| 3 | Manual | Automated submission is not possible due to CAPTCHA, phone verification, or mandatory account creation. TraceBurn launches a guided wizard that opens a browser window and walks you through each step. |

---

## Re-list Risk Explanations

| Risk Level | Meaning |
|---|---|
| High | This broker is known to re-list removed records frequently, sometimes within days or weeks. Re-verification at T+7, T+30, and T+90 is strongly recommended. |
| Medium | Re-listing occurs occasionally. Standard re-verification schedule (T+7, T+30, T+90) is sufficient. |
| Low | Re-listing is rare. Re-verification is still performed on schedule as a precaution. |

---

## PeopleConnect Network Note

BeenVerified, TruthFinder, InstantCheckmate, PeopleLooker, and USSearch are operated by or affiliated with PeopleConnect, Inc. Submitting an opt-out through one of these brokers **may** propagate to some or all others in the network, but this is not guaranteed. TraceBurn submits opt-outs to each broker individually to ensure coverage.
