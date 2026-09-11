# Why this is here

Every run in this directory reported alerts, and every one of those alerts is a
FALSE POSITIVE caused by bug 14 (see nazmul.todo, 2026-09-10 09:00 section).

`_check_string_sanitizers` called every selected sanitizer with a plain string
whatever its declared parameter type, then did `if triggered:` on the result.
Sanitizers return `bool` OR `(bool, detail)` -- and a 2-tuple is ALWAYS truthy,
`(False, '')` included. So every tuple-returning sanitizer fired on every string
argument of every input.

The appium run's 62 alerts collapse to one signature,
`['check_file_access', 'check_process_and_fd_leaks', 'check_unhandled_promise_rejection']`,
all three from BASE_MANDATORY_SANITIZERS, on mojibake produced by the
pre-parser-fix input path. Nothing here is evidence about any target.

Not deleted, because it is the before-half of the bug-14 evidence.
