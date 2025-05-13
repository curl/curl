<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# On AI use in curl

These are guidelines for AI use when contributing to curl.

## For security reports and other issues

If you asked an AI tool to find problems in curl, you **must** make sure to
reveal this fact in your report.

You must also double-check the findings carefully before reporting them to us
to validate that the issues are indeed existing and working exactly as the AI
says. AI-based tools frequently generate inaccurate or fabricated results.

Further: it is *rarely* a good idea to just copy and paste an AI generated
report to the project. Those generated reports typically are too wordy and
rarely to the point (in addition to the common fabricated details). If you
actually find a problem with an AI and you have verified it yourself to be
true: write the report yourself and explain the problem as you have learned
it. This makes sure the AI-generated inaccuracies and invented issues are
filtered out early before they waste more people's time.

As we take security reports seriously, we investigate each report with
priority. This work is both time and energy consuming and pulls us away from
doing other meaningful work. Fake and otherwise made up security problems
effectively prevent us from doing real project work and make us waste time and
resources.

We ban users immediately who submit made up fake reports to the project.

## For pull requests

When contributing content to the curl project, you give us permission to use
it as-is and you must make sure you are allowed to distribute it to us. By
submitting a change to us, you agree that the changes can and should be
adopted by curl and get redistributed under the curl license. Authors should
be explicitly aware that the burden is on them to ensure no unlicensed code is
submitted to the project.

This is independent if AI is used or not.

When contributing a pull request you should of course always make sure that
the proposal is good quality and a best effort that follows our guidelines. A
basic rule of thumb is that if someone can spot that the contribution was made
with the help of AI, you have more work to do.

We can accept code written with the help of AI into the project, but the code
must still follow the code standards, be written clearly, be documented,
feature test cases and adhere to all the normal requirements we have.

## For translation

Translation services help users write reports, texts and documentation in
non-native languages and we encourage and welcome such contributors and
contributions.

As AI-based translation tools sometimes have a way to make the output sound a
little robotic and add an "AI tone" to the text, you may want to consider
mentioning that you used such a tool. Failing to do so risks that maintainers
wrongly dismiss translated texts as AI slop.
