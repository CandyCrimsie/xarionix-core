# Разработка Python-модуля

SDK находится в `sdk/python`. Установка в отдельное окружение разработчика:

Полная последовательность сборки и запуска:
[Stateful Hello Business](../examples/modules/hello-business-stateful/README.md).

```bash
python -m pip install ./sdk/python
python -m xarionix_sdk check hello:module --manifest manifest.json
python -m xarionix_sdk metadata hello:module --manifest manifest.json --output distribution/payload/resources
```

CLI импортирует **проверенный локальный** developer entry. Core никогда не
импортирует код uploaded package. Сборка и Ed25519 подпись выполняются штатными
`scripts.runtime_artifact` и `scripts.xpkg`; private signing key остаётся у
издателя, не в module image, Web или SDK metadata.

```python
from xarionix_sdk import Module

module = Module(id="example-module", namespace="example", version="1.0.0")

@module.operation("items-read", permission="example.items.read")
async def read(ctx, payload):
    return {}

if __name__ == "__main__":
    module.serve()
```

По умолчанию request/response — закрытый пустой object. Для бизнес-полей задайте
`request` и `response` schemas. V1 поддерживает закрытые objects, bounded arrays
и strings, integer/number/boolean/null, required, enum и числовые bounds. External
refs, regex, произвольные schema vocabularies не поддерживаются. Payload должен
соответствовать schema; возврат произвольного object без декларации отклоняется.
SDK не предоставляет токены или административные разрешения.

Stateful пример — `examples/modules/hello-business-stateful`, версии 1.1.x и
следующие. Старый 6A `hello-business` остаётся volatile regression-примером:
автоматического импорта его памяти нет. Первичная stateful initialization явно
показывает schema 0 в новом approved plan. Перед остановкой прежнего процесса
оператор должен отдельно сохранить нужные данные; SDK не объявляет пустую новую
SQLite базу миграцией существующей памяти. Откат к пакету без storage capability
при существующем allocation блокируется.

Handler — async функция; cooperative deadline не является sandbox для произвольного
Python кода. Принудительные timeout, resource/isolation controls и publisher trust
проверяются существующими Core/Agent. SDK service слушает только loopback, имеет
bounded concurrency, `/health/live`, `/health/ready`, `/version`, не отражает
исключения/headers/payload в логах и дожидается активных requests при shutdown.

Изменение зарегистрированных operations после генерации контракта запрещено.
Изменение permissions/schemas/version требует новой metadata, package signature
и штатного approval. JSON limits действуют и на UTF-8 bytes, и на глубину/число
элементов. Company partitioning — ответственность SQL handlers, а не замена
серверной проверки membership в Core.
