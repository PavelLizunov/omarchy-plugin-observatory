# AI Localization Review Pack: Dogfooding Checklist & Standards

Настоящий документ представляет собой нормативный пакет правил, контрольных списков (dogfooding checklist) и рецептов CI-автоматизации для проектирования, разработки и ревью локализации (i18n / l10n) плагинов Omarchy и сопутствующих веб-интерфейсов обсерватории.

---

## 1. Экосистемный контекст и фактура обсерватории

Текущий корпус содержит **2 844 записи в 286 чанках**. Числа для публичного использования должны браться только из сгенерированного Claim Ledger конкретного draft-релиза.

Исторический эвристический отчёт `reports/deep_i18n_and_hardware.json` анализировал другой snapshot и может использоваться только как исходная гипотеза, а не как текущая статистика локализации. Нарратив о форках ради перевода в `LAUNCH_PLAN_AND_HANDOFF.md` также требует отдельного доказательного пакета перед публичным числовым утверждением.

Требования ниже основаны на принципе dogfooding и общих практиках W3C Internationalization, Unicode CLDR, IETF BCP 47 и WAI-ARIA. Они не зависят от неподтверждённой доли мультиязычных плагинов.

---

## 2. Фундаментальные архитектурные принципы

### Принцип 1: Natural-Language UI Must Use Locale Keys
* **Запрет сырых строк:** Любой естественный язык, отображаемый конечному пользователю в графическом интерфейсе (заголовки, подписи полей, метки кнопок, подсказки, текст ошибок, статусных уведомлений), **обязан** извлекаться динамически по ключу локали (`locale key`).
* **Иерархические семантические ключи:** Ключи должны быть структурированы по домену и компоненту в формате `<domain>.<component>.<element>.<state_or_property>` (например: `plugin.header.title`, `network.status.connected`).
* **Запрет строковой конкатенации:** Категорически запрещается собирать фразы из фрагментов через оператор сложения (`+`) или шаблонные строки (`${prefix} ${variable}`). Разный порядок слов в языках мира делает такую конкатенацию нелокализуемой. Все параметры передаются как именованные аргументы через шаблоны интерполяции.

### Принцип 2: Stable IDs & Technical Code Untranslated
* **Неизменяемость технического слоя:** Любые системные идентификаторы, машинные протоколы и программные интерфейсы **никогда не переводятся** и не зависят от текущего языка пользователя:
  1. **Идентификаторы плагинов и манифестов:** Поля `id`, `namespace`, `version`, `schemaVersion`.
  2. **Системные шины и IPC:** Имена интерфейсов D-Bus, пути объектов, сигналы, методы (например: `org.freedesktop.UPower`, `org.mpris.MediaPlayer2`).
  3. **Схемы данных и хранилища:** Имена таблиц и колонок SQLite, ключи JSON-конфигураций, переменные состояния `GSettings` / `KConfig`.
  4. **Процессы и системные вызовы:** Команды CLI, имена бинарных файлов, флаги параметров в массивах `argv` (например: `["nmcli", "--terse", "device"]`).
  5. **Телеметрия и логирование:** Технические коды ошибок (`EACCES`, `ERR_CONNECTION_REFUSED`), имена внутренних событий, диагностические трейсы.
  6. **Внутренние константы:** Значения перечислений (`enum`), токены тем (`colorRole: "primary"`).

---

## 3. Лингвистические и культурные стандарты (W3C / Unicode CLDR)

### 3.1. Множественные формы (Pluralization)
* **Запрет бинарной логики:** Конструкция вида `count === 1 ? formA : formB` недопустима. В славянских, семитских и балтийских языках действует от трех до шести грамматических категорий множественности.
* **Соответствие категориям CLDR:** Форматирование обязано использовать все применимые для целевой локали категории:
  * `zero`
  * `one`
  * `two`
  * `few`
  * `many`
  * `other`
* **Синтаксис сообщений:** Рекомендуется синтаксис стандарта **ICU MessageFormat**:
  `{count, plural, one {# file} few {# files} many {# files} other {# files}}`.

### 3.2. Числа, проценты и валюты (Numbers & Quantities)
* **Десятичные и разделительные знаки:** Запрещено жестко прошивать точку (`.`) или запятую (`,`). Использовать стандартные системные локали (`Intl.NumberFormat` в JavaScript, `Qt.locale().toString()` в QML/C++).
* **Группировка разрядов:** Разделитель тысяч (неразрывный пробел, запятая, апостроф) форматируется строго через движок локализации.
* **Знаки валют и процентов:** Положение знака (`%`, `$`, `€`) относительно числа и наличие пробела между ними определяется локалью (например: `50%` vs `50 %`).

### 3.3. Даты, время и календари (Dates & Calendars)
* **Формат времени (12h / 24h):** Интерфейс должен автоматически подстраиваться под системные настройки пользователя (AM/PM или 24-часовая шкала), а не фиксировать один формат.
* **Порядок следования компонентов даты:** Разрешено использование только локализованных форматов (`Intl.DateTimeFormat`, `Qt.formatDateTime(dt, Locale.ShortFormat)`). Нельзя склеивать строки вида `year + "-" + month + "-" + day`.
* **Относительное время:** Метки типа «только что», «5 минут назад», «вчера» должны генерироваться через API относительного времени (`Intl.RelativeTimeFormat`), исключая самописные тернарные цепочки.

---

## 4. Верстка, динамика текста и RTL (W3C Layout Standards)

### 4.1. Запас на расширение текста (Text Expansion Allowance)
* **W3C правило расширения длины строк:**
  * Для коротких строк (до 10 символов — кнопки, лейблы табов, заголовки колонок) длина перевода на немецкий, французский или русский языки может превышать английский оригинал на **100%–200%**.
  * Для средних строк (до 50 символов) запас должен составлять не менее **30%–50%**.
* **Запрет жестких пиксельных рамок:**
  * Запрещены фиксированные размеры контейнеров с текстом (`width: 80px`, `height: 24px`).
  * Разметка должна быть гибкой: автоматическое растяжение кнопок, эластичные сетки (`Layout.preferredWidth: -1`, `flex-wrap: wrap`).
* **Контроль переполнения и обрезки:**
  * Текст описаний и статусов обязан поддерживать перенос (`wrapMode: Text.WordWrap`, `overflow-wrap: break-word`).
  * Если по дизайну необходим эллипсис (`elide: Text.ElideRight`, `text-overflow: ellipsis`), элемент обязан сопровождаться доступным всплывающим тултипом или диалогом с полным не обрезанным текстом.

### 4.2. Двунаправленный текст и поддержка RTL (Right-to-Left)
* **Поддержка направлений BCP 47:** Полная готовность интерфейса к локалям с письмом справа налево (арабский `ar`, иврит `he`, фарси `fa`, урду `ur`).
* **Логические свойства (W3C CSS Logical Properties / QML Mirrored Layouts):**
  * В CSS: использование `margin-inline-start`, `margin-inline-end`, `padding-inline-start`, `inset-inline-start` вместо `left` и `right`.
  * В QML: использование `LayoutMirroring.enabled: Qt.locale().textDirection === Qt.RightToLeft` и `LayoutMirroring.childrenInherit: true`.
* **Правила зеркалирования графических символов:**
  * **Зеркалируются:** Стрелки направления назад/вперед, иконки пагинации, прогресс-бары, иконки списков с маркерами.
  * **Не зеркалируются:** Органы управления мультимедиа (кнопки Play, Pause, перемотка), часы со стрелками, международные брендовые логотипы.
* **Изоляция двунаправленных фрагментов (Bidi Isolation):**
  * При вставке динамических данных (пути к файлам, URL, имена процессов, технические токены) в локализованный текст они должны изолироваться через тег `<bdi>` (в HTML) или управляющие символы Unicode FSI/PDI (`\u2068...\u2069`), чтобы предотвратить разрушение порядка чтения.

---

## 5. Доступность (Accessibility / a11y)

* **Синхронизация атрибутов языка:**
  * Корневой элемент веб-документа или приложения обязан иметь корректный атрибут `lang` (например: `<html lang="en">` или `<html lang="pt-BR">`).
  * Вкрапления цитат или интерфейсов на другом языке должны снабжаться локальным атрибутом `lang`.
* **Локализация доступных имен (Accessible Names):**
  * Все атрибуты доступности: `Accessible.name`, `Accessible.description`, `aria-label`, `aria-description`, `alt`, `title` **обязаны** использовать ключи локализации. Запрещено оставлять англоязычные aria-лейблы в локализованном интерфейсе.
* **Синтез речи и динамические уведомления:**
  * Области динамических обновлений (`aria-live`, экранные дикторы) должны формировать оповещения на текущем выбранном языке интерфейса.
* **Шрифтовая типографика:**
  * Стек шрифтов должен содержать глифы для всех поддерживаемых письменностей (латиница, кириллица, CJK, арабское письмо). Запрещено использовать моно-шрифты без кириллического или расширенного набора символов, вызывающие артефакты подстановки глифов (tofu boxes).

---

## 6. Паритет заявлений локализации (Claim Parity)

* **Принцип 100% паритета ключей:**
  * Если манифест плагина, `README.md` или описание в каталоге заявляет поддержку языка (например: «Поддержка EN, PT-BR, DE, RU»), языковой файл **обязан** содержать 100% ключей базовой эталонной локали.
  * Запрещены псевдопереводы, где переведено 3 кнопки из 50, а остальные ключи отсутствуют.
* **Паритет переменных интерполяции:**
  * Имена и количество переменных подстановки (`{userName}`, `{count}`, `{percent}`) во всех языковых вариантах должны быть идентичны эталонному словарю.
* **Запрет ложных значений-заглушек:**
  * Ключ не должен возвращать собственное имя вместо перевода (например: `"actions.save": "actions.save"`). Непереведенные строки должны выявляться на этапе сборки.

---

## 7. Практический Dogfooding Checklist (для авторов и ревьюеров)

При создании или проверке любого плагина и веб-экрана сверяйтесь со следующей таблицей:

| № | Область проверки | Вопрос для самопроверки | Статус |
|---|---|---|---|
| **1** | **Строковая изоляция** | Нет ли в QML/HTML/JSX разметке захардкоженного текста? Все ли видимые строки вынесены в ключи локализации? | [ ] |
| **2** | **Технический слой** | Остались ли неизменными технические идентификаторы (D-Bus интерфейсы, ключи JSON, флаги CLI, имена таблиц)? | [ ] |
| **3** | **Множественные формы** | Используется ли плюрализация CLDR вместо бинарного оператора `count === 1`? | [ ] |
| **4** | **Числа и даты** | Применяются ли платформенные форматтеры (`Intl`, `Qt.locale()`) вместо конкатенации строк? | [ ] |
| **5** | **Запас верстки** | Предусмотрен ли запас 30–50% (и до 200% для коротких кнопок) по ширине? Отсутствуют ли фиксированные ширины? | [ ] |
| **6** | **RTL и логические свойства** | Работает ли интерфейс корректно в режиме RTL? Используются ли логические отступы (`inline-start`)? | [ ] |
| **7** | **Доступность (a11y)** | Локализованы ли атрибуты `Accessible.name`, `Accessible.description`, `aria-label`? | [ ] |
| **8** | **Паритет словарей** | Содержит ли каждый заявленный язык 100% ключей без пропусков по сравнению с эталонной локалью? | [ ] |
| **9** | **Паритет аргументов** | Совпадают ли имена переменных интерполяции во всех файлах перевода? | [ ] |
| **10** | **CI-проверки** | Проходит ли PR автоматические линтеры ключей и тесты псевдолокализации? | [ ] |

---

## 8. Автоматизация и CI Quality Gates

### 8.1. CI-проверка 1: Контроль паритета ключей локализации (Key Parity Check)
Скрипт проверяет, что все файлы перевода содержат точно такой же набор ключей, как и эталонный файл (`en.json`):

```bash
#!/usr/bin/env bash
set -euo pipefail

REF_LOCALE="locales/en.json"
FAILED=0

for locale_file in locales/*.json; do
    if [ "$locale_file" == "$REF_LOCALE" ]; then
        continue
    fi

    # Поиск отсутствующих ключей
    missing_keys=$(jq -r --slurpfile ref "$REF_LOCALE" '
        ($ref[0] | keys) - (keys) | .[]
    ' "$locale_file")

    if [ -n "$missing_keys" ]; then
        echo "❌ [ERROR] File $locale_file is missing keys:"
        echo "$missing_keys"
        FAILED=1
    fi

    # Поиск лишних ключей, отсутствующих в эталоне
    extra_keys=$(jq -r --slurpfile ref "$REF_LOCALE" '
        (keys) - ($ref[0] | keys) | .[]
    ' "$locale_file")

    if [ -n "$extra_keys" ]; then
        echo "⚠️ [WARN] File $locale_file has orphan keys:"
        echo "$extra_keys"
    fi
done

exit $FAILED
```

### 8.2. CI-проверка 2: Поиск захардкоженного текста в разметке UI
Линтер на базе регулярных выражений или AST для выявления сырых строковых литералов в UI-свойствах (`text: "..."`, `<button>Text</button>`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# Сканирование QML файлов на наличие жестко захардкоженных строк в свойствах text, title, label
# Исключаются вызовы qsTr, i18n.t, пустые строки и привязки к свойствам
VIOLATIONS=$(grep -rnE '^\s*(text|title|label|placeholderText)\s*:\s*"[^"]{2,}"' . \
    --include="*.qml" \
    --exclude-dir="node_modules" \
    --exclude-dir=".git" || true)

if [ -n "$VIOLATIONS" ]; then
    echo "❌ [REJECT] Hardcoded natural-language UI strings detected in QML markup:"
    echo "$VIOLATIONS"
    exit 1
else
    echo "✅ [PASS] No raw hardcoded UI text literals detected in QML components."
fi
```

### 8.3. CI-проверка 3: Валидация аргументов подстановки
Проверка совпадения именованных параметров интерполяции (`{variable}`) между локалями:

```bash
#!/usr/bin/env bash
set -euo pipefail

python3 - << 'EOF'
import json
import re
import sys
from pathlib import Path

locales_dir = Path("locales")
ref_file = locales_dir / "en.json"

if not ref_file.exists():
    print("Reference locale not found.")
    sys.exit(0)

with open(ref_file, encoding="utf-8") as f:
    ref_data = json.load(f)

param_pattern = re.compile(r"\{([a-zA-Z0-9_]+)\}")
has_errors = False

for target_file in locales_dir.glob("*.json"):
    if target_file.name == "en.json":
        continue
    with open(target_file, encoding="utf-8") as f:
        target_data = json.load(f)

    for key, ref_text in ref_data.items():
        if key not in target_data or not isinstance(ref_text, str):
            continue
        target_text = target_data[key]
        if not isinstance(target_text, str):
            continue

        ref_params = set(param_pattern.findall(ref_text))
        target_params = set(param_pattern.findall(target_text))

        if ref_params != target_params:
            print(f"❌ Parameter mismatch in {target_file.name} for key '{key}':")
            print(f"   Expected: {ref_params}, Got: {target_params}")
            has_errors = True

if has_errors:
    sys.exit(1)
print("✅ [PASS] All interpolation parameters match reference locale.")
EOF
```

### 8.4. Тестирование псевдолокализацией (Pseudo-Localization Pipeline)
Перед релизом интерфейс прогоняется через генератор псевдолокализации (расширение текста на 40% с заменой символов на диакритические знаки: `[!!! Ṗŀŭģĭŋ Ťĭťŀē !!!]`):
1. Позволяет мгновенно увидеть невынесенные захардкоженные строки (они останутся на обычном английском).
2. Позволяет выявить поломку контейнеров и обрезку текста из-за недостаточного запаса по ширине.
3. Проверяет корректность кодировки UTF-8 в системе рендеринга шрифтов.

---

## 9. Матрица вердиктов для ревью (Review Rubric)

| Вердикт | Условия вынесения | Действие в CI/PR |
|---|---|---|
| **`PASS`** | 100% пользовательских строк вынесены в семантические ключи; технические идентификаторы не затронуты; множественные формы поддержаны через CLDR; даты и числа локализованы; верстка поддерживает запас 30–50% и RTL; обеспечен 100% паритет ключей во всех заявленных локалях; атрибуты доступности переведены; CI-гейты пройдены. | Слияние разрешено. |
| **`WARNING`** | Обнаружены некритичные замечания: отсутствуют тултипы при эллипсисе длинного текста; отсутствует один второстепенный язык из заявленного расширенного набора (при наличии корректного fallback); незначительные отклонения в логических отступах без разрушения компоновки. | Требует исправления перед мажорным релизом. |
| **`REJECT`** | Критические дефекты: наличие захардкоженного естественного языка в разметке UI; локализованы системные D-Bus интерфейсы, CLI-команды или ключи конфигурации; использован бинарный тернарный оператор плюрализации; разрушение верстки или нечитаемая обрезка текста; отсутствие экранирования bidi для динамических данных; расхождение аргументов интерполяции, приводящее к сбою рантайма. | Слияние заблокировано. |

---

## 10. Эталонные реализации компонентов (Reference Implementations)

Ниже приведены нормативные примеры реализации интерфейсов. Обратите внимание: **в разметке UI полностью отсутствует захардкоженный естественный язык** — все текстовые свойства привязаны исключительно к семантическим ключам локализации, токенам и локализованным форматтерам.

### 10.1. Пример для QML / Quickshell

```qml
import QtQuick
import QtQuick.Layouts
import QtQuick.Controls

Item {
    id: root

    // 1. Технический слой: стабильные системные идентификаторы не локализуются
    readonly property string serviceDbusInterface: "org.omarchy.DeviceManager"
    readonly property string serviceDbusPath: "/org/omarchy/DeviceManager"

    // Модель локализации (загружается из i18n сервиса)
    property var i18nManager

    // Отражение верстки для поддержки RTL языков
    LayoutMirroring.enabled: Qt.locale().textDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        // Заголовок компонента: привязка к семантическому ключу
        Label {
            text: root.i18nManager.t("device_panel.header.title")
            font.bold: true
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        // Информационное поле: форматирование числа и множественного числа
        Label {
            text: root.i18nManager.t("device_panel.status.connected_count", {
                count: deviceService.connectedDevicesCount
            })
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }

        // Блок с временной меткой: системный локализованный формат даты и времени
        Label {
            text: root.i18nManager.t("device_panel.status.last_sync", {
                timestamp: Qt.formatDateTime(deviceService.lastSyncTime, Locale.ShortFormat)
            })
            Layout.fillWidth: true
            elide: Text.ElideRight
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            // Кнопка действия: адаптивная ширина без фиксации в пикселях
            Button {
                text: root.i18nManager.t("device_panel.actions.sync_now.label")
                Accessible.name: root.i18nManager.t("device_panel.actions.sync_now.accessible_name")
                Accessible.description: root.i18nManager.t("device_panel.actions.sync_now.accessible_description")
                Layout.preferredWidth: -1
                Layout.minimumWidth: 100
                onClicked: deviceService.triggerSync()
            }

            // Кнопка настроек
            Button {
                text: root.i18nManager.t("device_panel.actions.settings.label")
                Accessible.name: root.i18nManager.t("device_panel.actions.settings.accessible_name")
                Layout.preferredWidth: -1
                onClicked: settingsDialog.open()
            }
        }
    }
}
```

### 10.2. Пример для Web UI (React / TypeScript / W3C A11y)

```tsx
import React from "react";
import { useTranslation } from "react-i18next";

interface DeviceMonitorCardProps {
  deviceCount: number;
  lastUpdated: Date;
  onRefresh: () => void;
  statusKey: string;
}

export const DeviceMonitorCard: React.FC<DeviceMonitorCardProps> = ({
  deviceCount,
  lastUpdated,
  onRefresh,
  statusKey,
}) => {
  const { t, i18n } = useTranslation();

  // Локализованное форматирование даты через стандартный браузерный API
  const formattedDate = new Intl.DateTimeFormat(i18n.language, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(lastUpdated);

  return (
    <article
      className="monitor-card"
      dir={i18n.dir()}
      aria-labelledby="card-heading"
    >
      <header className="monitor-card__header">
        <h2 id="card-heading">
          {t("monitor.card.heading.title")}
        </h2>
        <span
          className="badge"
          data-status={statusKey}
          role="status"
        >
          {t(`monitor.status.${statusKey}`)}
        </span>
      </header>

      <div className="monitor-card__body">
        {/* Плюрализация по правилам CLDR */}
        <p className="device-count">
          {t("monitor.card.devices_detected", { count: deviceCount })}
        </p>

        {/* Дата обновления с изоляцией двунаправленного текста */}
        <p className="update-timestamp">
          {t("monitor.card.last_updated_at", {
            time: formattedDate,
          })}
        </p>
      </div>

      <footer className="monitor-card__actions">
        {/* Локализованная кнопка и доступный лейбл */}
        <button
          type="button"
          onClick={onRefresh}
          className="btn btn--primary"
          aria-label={t("monitor.card.actions.refresh_aria")}
        >
          {t("monitor.card.actions.refresh_label")}
        </button>
      </footer>
    </article>
  );
};
```

---

## 11. Заключение

Соблюдение данного руководства гарантирует:
1. Исключение повторения антипаттернов десктопного маркетплейса (таких как клонирование репозиториев ради перевода).
2. Полную совместимость кода с мировыми стандартами доступности и интернационализации W3C.
3. Надежную автоматическую валидацию в CI-конвейере, исключающую попадание в релиз сломанной верстки, пропущенных переводов или ошибок форматирования параметров.
