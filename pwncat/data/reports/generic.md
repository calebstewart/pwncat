# {{ platform.channel | remove_rich }} | {{ session.run("enumerate", types=["system.hostname"]) | first_or_none | attr_or("hostname", "unknown hostname") }}

This enumeration report was automatically generated with [pwncat](https://github.com/calebstewart/pwncat).
The report was generated on {{ datetime }}.

## Common System Information

{{ [
    ["**Platform**", platform.name],
    ["**Architecture**", session.run("enumerate", types=["system.arch"]) | first_or_none | title_or_unknown ],
    ["**Hostname**", session.run("enumerate", types=["system.hostname"]) | first_or_none | title_or_unknown],
    ["**ASLR**", session.run("enumerate", types=["system.aslr"]) | first_or_none | title_or_unknown],
    ["**Container**", session.run("enumerate", types=["system.container"]) | first_or_none | title_or_unknown],
    ["**Distribution**", session.run("enumerate", types=["system.distro"]) | first_or_none | title_or_unknown],
] | table(headers=False) }}

{% if session.run("enumerate", types=["implant.*"]) %}
## Installed Implants
{% for implant in session.run("enumerate", types=["implant.*"]) %}
- {{ implant | title_or_unknown }}
{% endfor %}

{% endif %}
{% if session.run("enumerate", types=["escalate.*"]) %}
## Escalation Methods
{% for escalation in  session.run("enumerate", types=["escalate.*"]) %}
- {{ escalation | title_or_unknown }}
{% endfor %}

{% endif %}
{% if session.run("enumerate", types=["ability.*"]) %}
## Abilities
{% for ability in session.run("enumerate", types=["ability.*"]) %}
- {{ ability | title_or_unknown }}
{% endfor %}

{% endif %}
{% if session.run("enumerate", types=["tamper"]) %}
## Modified Settings and Files
{% for tamper in session.run("enumerate", types=["tamper"]) %}
- {{ tamper | title_or_unknown }}
{% endfor %}

{% endif %}
## Enumerated Users
{% for user in session.iter_users() %}
- {{ user | title_or_unknown }}
{% endfor %}

## Enumerated Groups
{% for group in session.iter_groups() %}
- {{ group | title_or_unknown }}
{% endfor %}

{% block platform %}
{% endblock %}
