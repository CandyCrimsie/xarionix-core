# Миграции данных модуля

Миграции принадлежат SDK-модулю и выполняются внутри его изолированного runtime.
Core не импортирует Python из пакета и не выполняет uploaded SQL. В signed SDK
metadata входят последовательные номера и SHA-256 migrations. Пакет и OCI image
содержат одинаковую декларацию. Hello Business проверяет её перед открытием БД.

1. Загрузить проверенный новый `.xpkg`, создать и утвердить Install Plan.
2. Остановить writer. Создать и утвердить deployment `backup`.
3. Подготовить `upgrade` с `backup_id` и `allow_migration=true`.
4. Проверить digest и подтвердить свежим MFA. Backup должен соответствовать
   installation, epoch, текущей schema и allocation revision.
5. Agent проверяет сохранённую БД и backup, останавливает предыдущий runtime,
   запускает exact approved image. SDK выполняет migrations одной транзакцией.
6. Только успешные health/schema checks и ACK разрешают Gateway доступ.

SDK запрещает ATTACH/DETACH, extension loading, изменение journal policy и
самостоятельный COMMIT/ROLLBACK внутри migration. При исключении транзакция
откатывается. Statement cache отключён: ранее скомпилированный COMMIT не обходит
SQLite authorizer. Проверяются integrity и schema compatibility.

```mermaid
sequenceDiagram
  participant O as Platform Admin + MFA
  participant C as Core
  participant A as Agent
  participant M as Module SQLite
  O->>C: Backup и migration plan
  C->>A: Exact approved schema + fresh backup binding
  A->>M: Остановить writer, проверить текущую схему
  A->>M: Запустить новый image с migration approval
  M->>M: BEGIN + migrations + COMMIT
  M-->>A: Ready + schema version
  A-->>C: Verified receipt
```

Откат image не означает откат данных. Несовместимый `rollback` запрещён до запуска.
Нужно явно восстановить совместимый backup в новую epoch и затем запустить прежний
пакет. Если migration уже committed, а readiness не прошёл, данные автоматически
не откатываются: runtime закрыт для Gateway; оператор проверяет состояние через
`inspect`, затем выбирает исправление или restore. Нельзя обещать атомарность между
SQLite COMMIT и Core ACK через сеть.

```mermaid
flowchart TD
  U[Обновление пакета] --> S{Схема совместима?}
  S -->|Да| H[Запуск и health checks]
  S -->|Нет, требуется migration| B[Свежий backup + отдельное approval]
  B --> M[Транзакционная migration внутри модуля]
  M --> H
  R[Rollback image] --> K{Текущая schema поддерживается?}
  K -->|Да| H
  K -->|Нет| X[Отказ до запуска]
  X --> E[Явный restore в новую data epoch]
  E --> H
```
