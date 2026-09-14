# X announcement — EN, long post

Draft for posting after both repositories are updated. Gemini attribution and the account of the work come from the author. The figure 3,086 corresponds to stored reports; it does not establish independent verification of that many unique repositories. Count definition and example sources: [README](../README.md), [methodology](../METHODOLOGY.md) and [source notes](../docs/source-notes.md).

---

Before building my own Omarchy plugin, I asked Gemini 3.8 Flash to study community plugin code as a basis for an agent skill.

I collected the resulting 3,086 review records in Omarchy Plugin Observatory and put the development and review guidance into a separate skill, Omarchy Plugin Patterns.

A few examples from the research:

One media widget has a two-second timer that attempts to start seven playerctl processes. Some results feed the bar tooltip even when the widget's popup is closed. A rule like “close the popup, stop all updates” would overlook the bar's own use of that data.

In wg-omarchy, the system password is entered directly in the widget and passed through stdin to sudo -S. The user initiates the connection, but the plugin's code still has access to the password.

A component in omarchy-thunderbird-mail-checker receives events through a Unix socket. Observatory links to that implementation as an example of exchanging events between components.

Localization raised a separate maintenance question. Omarchy has localized copies of plugins, where maintaining a translation also means maintaining a separate copy of the code and bringing over changes from the original. The skill covers separating translations from logic and keeping them in one repository, using the mechanisms the shell supports.

Omarchy Plugin Observatory:
https://github.com/PavelLizunov/omarchy-plugin-observatory

Omarchy Plugin Patterns:
https://github.com/PavelLizunov/omarchy-plugin-patterns

This is AI-assisted code analysis, without running the plugins. Some findings have been checked, and errors in the analysis are documented separately with corrections and links to the source.

If you use Omarchy plugins or write your own, what problems do you run into? I'd like to use your experience to improve the reviews and the skill.
