# Evaluation

## Evaluation Design

For the evaluation, 5 pages were selected at random from the official MITRE Enterprise ATT&CK website. General-purpose chatbots were asked to select the pages randomly, subject to the restriction that the selection must not include malware, campaign, or other entity categories that are outside the scope of this chatbot.

Two questions were designed from each selected page, resulting in 10 evaluation questions. Questions from each page were asked of the implemented chatbot as a multi-turn conversation of two to four turns. The same evaluation was also repeated in a single-turn setting.

In addition, 10 boundary-handling questions covering irrelevant, ambiguous, and out-of-scope inputs were tested. For irrelevant and out-of-scope requests, the chatbot correctly redirected the user to its main ATT&CK-focused scope instead of generating unsupported information. For ambiguous requests, it handled the uncertainty appropriately rather than presenting an unsupported interpretation as fact.

## Results

All 10 in-scope questions were answered correctly and completely in both the multi-turn and single-turn evaluations. Evaluation was performed at two levels: the factual correctness and completeness of each answer were manually checked, and the source identified by the chatbot was separately verified to ensure that it was the correct supporting source for the answer. All 10 boundary-handling questions were also handled correctly.

The evaluation questions and the corresponding answers are available as CSV files in the `evaluation` folder.

The evaluation therefore produced full scores across all criteria used in this experiment:

| Criterion | Assessment | Result |
| :---- | :---- | ----: |
| Answer correctness | The factual content of each answer was manually checked against the selected ATT&CK page and its supporting evidence. | 10/10 (100%) |
| Answer completeness | Each answer was checked for complete coverage of the information requested by the question. | 10/10 (100%) |
| Supporting-source correctness | The source identified by the chatbot was independently checked to confirm that it was the precise source supporting the answer. | 10/10 (100%) |
| Multi-turn performance | Correctness, completeness, and source grounding were checked across conversations of two to four turns. | 10/10 (100%) |
| Single-turn performance | The same in-scope questions were repeated independently in a single-turn setting. | 10/10 (100%) |
| Boundary handling | Irrelevant, ambiguous, and out-of-scope inputs were checked for safe handling without unsupported claims. | 10/10 (100%) |

Evaluation can nevertheless be more complex than this focused assessment. A broader evaluation could include a larger and more diverse sample, adversarial and failure-case scenarios, automated measurements of answer relevance, faithfulness, and context precision, as well as additional robustness tests.
