#!/usr/bin/env python3
"""Organize existing evidence for Harness file browsing; never run remote tests.

Usage: python3 organize-evidence.py /path/to/omarchy-workspace
Generated copies stay local; original evidence is never edited.
"""
import hashlib
from pathlib import Path
import re
import shutil
import sys

workspace = Path(sys.argv[1]).resolve()
output = workspace / 'report' / '2026-09-28'
report = workspace / 'report-backup/reports/omarchy-runtime-acceptance-2026-09-28.md'
groups = {
    '01-report': [('Полный отчёт', report, 'report.md')],
    '02-screenshots': [
        ('Исходный рабочий стол, grim', workspace / 'artifacts/screenshots/baseline.png', 'baseline.png'),
        ('Скриншот через команду из скилла', workspace / 'artifacts/screenshots/skill-capture.png', 'skill-capture.png')],
    '03-vpnrouter': [], '04-tts': [], '05-observatory': [],
    '06-agent-and-state': [], '07-reproduction': []
}
for source in sorted((workspace / 'artifacts/evidence').iterdir()):
    if not source.is_file():
        continue
    name = source.name
    if name.startswith('vpn-'):
        group = '03-vpnrouter'
    elif name.startswith('tts-'):
        group = '04-tts'
    elif name.startswith(('observatory-', 'validation-')):
        group = '05-observatory'
    else:
        group = '06-agent-and-state'
    groups[group].append((name, source, name))
for source in [workspace / 'check-skill-discovery.py', workspace / 'tts-component-check.qml',
               workspace / 'docs/specs/omarchy-night-test.md']:
    groups['07-reproduction'].append((source.name, source, source.name))

# Refuse to overwrite changed copies. Validate every input before writing.
for group, entries in groups.items():
    for _, source, name in entries:
        if not source.is_file() or source.is_symlink():
            raise RuntimeError(f'Unsafe or missing input: {source}')
        target = output / group / name
        if target.is_symlink() or (target.exists() and target.read_bytes() != source.read_bytes()):
            raise RuntimeError(f'Existing output differs: {target}')

lines = ['# Omarchy — отчёт и доказательства', '',
         'Проверка 28 сентября 2026 года. Это сохранённые результаты ночного прогона, не новая проверка.', '',
         '**Начните с [полного отчёта](01-report/report.md).**', '',
         'VPNRouter и TTS установлены и выключены. Прошли 440 отдельных тестов, ещё 5 JS-наборов и 12 QML-проверок VPNRouter.',
         'Остались ошибки экспорта Observatory и ограничения offscreen-проверки TTS. Живой UI плагинов не проверялся.', '',
         '## Скриншоты', '',
         'Это настоящие снимки рабочего стола, а не интерфейсов выключенных плагинов.', '',
         '### Через команду из скилла', '',
         '![Omarchy: захват через скилл](02-screenshots/skill-capture.png)', '',
         '### Исходное состояние', '',
         '![Omarchy: исходный рабочий стол](02-screenshots/baseline.png)', '',
         '## Файлы по папкам', '']
count = 0
for group, entries in groups.items():
    lines += [f'### {group}', '']
    for label, source, name in entries:
        target = output / group / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copy2(source, target)
        assert hashlib.sha256(source.read_bytes()).digest() == hashlib.sha256(target.read_bytes()).digest()
        suffix = ' — пустой stdout; exit code указан в status.txt и отчёте' if target.stat().st_size == 0 else ''
        lines.append(f'- [{label}]({group}/{name}){suffix}')
        count += 1
    lines.append('')
lines += ['`status.txt` относится к первому прогону: последующий успешный повтор Observatory находится в `observatory-unit-venv.log`.', '',
          'Исходные файлы и ZIP сохранены. Содержимое скопированных доказательств не изменено.', '']
index = output / 'README.md'
content = '\n'.join(lines)
if index.is_symlink() or (index.exists() and index.read_text() != content):
    raise RuntimeError('Existing index differs; inspect before replacing')
index.write_text(content)
for link in re.findall(r'\]\(([^)]+)\)', content):
    assert (output / link).is_file(), link
print(f'PASS: {count} byte-identical copies; all index links resolve. Open {index}')
